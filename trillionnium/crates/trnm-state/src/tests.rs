use super::governance::{
    is_sensitive_gov_param, validate_gov_param_value, GOV_ALLOWED_KEYS,
    GOV_KEYS_WITH_EXPLICIT_VALIDATORS, GOV_SCHEMA_INVALID_SAMPLES, GOV_SENSITIVE_KEYS,
};
use super::*;
use trnm_types::{
    GovProposalObject, GovProposalStatus, ProofType, TaskMetadata, TaskMeteringSnapshot,
    TaskObject, TaskStatus,
};

#[test]
fn put_and_version_update() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 7,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
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
    let r1 = st.put_task_new(t.clone()).unwrap();
    assert_eq!(r1.version, 1);

    let mut t2 = t;
    t2.status = TaskStatus::Assigned;
    let r2 = st.update_task(r1, t2).unwrap();
    assert_eq!(r2.version, 2);
}

#[test]
fn task_metering_snapshot_affects_state_root() {
    let mut without_metering = StateStore::new();
    let mut with_metering = StateStore::new();

    let base_task = TaskObject {
        task_id: 404,
        creator: "alice".into(),
        bounty: 25,
        status: TaskStatus::Completed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(40),
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    };

    let mut metered_task = base_task.clone();
    metered_task.metadata = Some(TaskMetadata {
        note: Some("metered task".into()),
        task_type: Some("inference".into()),
        input_hash: Some("ab".repeat(32)),
        model: None,
        provenance: None,
        metering: Some(TaskMeteringSnapshot {
            workload_class: "llm_inference".into(),
            metering_schema: "llm_token_meter_v1".into(),
            policy_snapshot_version: 2,
            receipt_hash: "cd".repeat(32),
            prompt_tokens: 144,
            generated_tokens: 55,
            decode_steps: 13,
            kv_bytes_moved: 4096,
            normalized_work_units: 987,
            prompt_token_weight: 3,
            generated_token_weight: 5,
            decode_step_weight: 7,
            kv_byte_weight: 11,
            min_accept_work_units: 100,
            challenge_success_bounty_base: 17,
            challenge_success_bounty_per_work_unit_num: 19,
            challenge_success_bounty_per_work_unit_den: 23,
            worker_completion_bonus_per_work_unit_num: 29,
            worker_completion_bonus_per_work_unit_den: 31,
            worker_slash_rebate_per_work_unit_num: 37,
            worker_slash_rebate_per_work_unit_den: 41,
        }),
            settlement: None,
    });

    without_metering.put_task_new(base_task).unwrap();
    with_metering.put_task_new(metered_task).unwrap();

    assert_ne!(
        without_metering.state_root(),
        with_metering.state_root(),
        "state_root must include task metering snapshots so audit-proof work-unit evidence cannot be silently omitted"
    );
}

#[test]
fn restore_task_rejects_unchallenged_terminal_retention_with_resolve_deadline() {
    let mut st = StateStore::new();

    st.restore_task(
        407,
        Some(TaskObject {
            task_id: 407,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained proof-window snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        st.get_task(407).is_none(),
        "restore_task must fail closed when an unchallenged terminal task keeps a resolve deadline even though only the proof-window snapshot should survive retention"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_resolve_deadline() {
    let mut st = StateStore::new();

    st.restore_task(
        408,
        Some(TaskObject {
            task_id: 408,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(0),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(408).is_none(),
        "restore_task must fail closed when a retained terminal collateral snapshot zeroes the resolve deadline that bounds proof-retention settlement"
    );
}

#[test]
fn restore_task_rejects_unchallenged_terminal_retention_with_stale_forfeit_marker() {
    let mut st = StateStore::new();

    st.restore_task(
        4081,
        Some(TaskObject {
            task_id: 4081,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained proof-window snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(4081).is_none(),
        "restore_task must fail closed when an unchallenged terminal proof-retention snapshot keeps a stale challenge-bond outcome without live collateral context"
    );
}

#[test]
fn restore_task_rejects_unchallenged_terminal_retention_with_zero_bond_marker() {
    let mut st = StateStore::new();

    st.restore_task(
        4082,
        Some(TaskObject {
            task_id: 4082,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained proof-window snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: Some(0),
            challenger: None,
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        st.get_task(4082).is_none(),
        "restore_task must fail closed when an unchallenged terminal proof-retention snapshot keeps a zero challenge-bond marker instead of canonical absence"
    );
}

#[test]
fn restore_task_allows_completed_retention_with_proof_window_snapshot_only() {
    let mut st = StateStore::new();

    let task = TaskObject {
        task_id: 4083,
        creator: "alice".into(),
        bounty: 25,
        status: TaskStatus::Completed,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("retained proof-window snapshot".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: None,
            provenance: None,
            metering: None,
                    settlement: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    };

    st.restore_task(4083, Some(task.clone()));

    assert_eq!(st.get_task(4083), Some(task));
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_challenger_but_no_bond() {
    let mut st = StateStore::new();

    st.restore_task(
        409,
        Some(TaskObject {
            task_id: 409,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: None,
            challenger: Some("bob".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        st.get_task(409).is_none(),
        "restore_task must fail closed when a retained terminal collateral snapshot keeps challenger identity but drops the posted challenge bond that funded the proof-retention audit trail"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_blank_challenger() {
    let mut st = StateStore::new();

    st.restore_task(
        4091,
        Some(TaskObject {
            task_id: 4091,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("   ".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(4091).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata keeps a posted challenge bond but the challenger identity is blank instead of canonical audit material"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_challenge_bond() {
    let mut st = StateStore::new();

    st.restore_task(
        40915,
        Some(TaskObject {
            task_id: 40915,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(0),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(40915).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata zeroes the posted challenge bond instead of preserving canonical collateral/proof audit material"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_noncanonical_challenger() {
    let mut st = StateStore::new();

    st.restore_task(
        4092,
        Some(TaskObject {
            task_id: 4092,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some(" bob ".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(4092).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata uses a whitespace-padded challenger identity instead of canonical collateral-proof audit material"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_system_identity() {
    let mut st = StateStore::new();

    st.restore_task(
        40921,
        Some(TaskObject {
            task_id: 40921,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("System".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(40921).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved system authority, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_reserved_resolve_authority_placeholder() {
    let mut st = StateStore::new();

    st.restore_task(
        40922,
        Some(TaskObject {
            task_id: 40922,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("56".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x10; 32]),
            result_hash: Some([0x20; 32]),
            reveal_salt: Some([0x30; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("Governance.Resolve_Authority".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(40922).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata aliases the challenger to the reserved governance.resolve_authority placeholder, even through mixed-case input"
    );
}

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_inverted_deadline_order() {
    let mut st = StateStore::new();

    st.restore_task(
        409,
        Some(TaskObject {
            task_id: 409,
            creator: "alice".into(),
            bounty: 25,
            status: TaskStatus::Completed,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("retained collateral trail".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
                            settlement: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(31),
            resolve_deadline_height: Some(29),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        st.get_task(409).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata inverts the challenged/deadline/resolve ordering"
    );
}

#[test]
fn version_conflict() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 1,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Open,
        proof_type: Default::default(),
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
    let r1 = st.put_task_new(t.clone()).unwrap();
    let _ = st.update_task(r1.clone(), t.clone()).unwrap();
    let err = st.update_task(r1, t).unwrap_err();
    assert!(err.contains("version conflict"));
}

#[test]
fn update_task_rejects_cross_domain_object_slot_even_when_version_matches() {
    let mut st = StateStore::new();
    let proposal_ref = st
        .put_proposal_new(GovProposalObject {
            proposal_id: 77,
            title: "slot owner".into(),
            proposer: "alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .expect("proposal insert should succeed");

    let err = st
        .update_task(
            proposal_ref,
            TaskObject {
                task_id: 77,
                creator: "mallory".into(),
                bounty: 5,
                status: TaskStatus::Assigned,
                proof_type: Default::default(),
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
                version: 999,
            },
        )
        .expect_err("task update must fail closed when the slot currently holds a proposal");

    assert!(err.contains("object type mismatch"));
    assert!(
        matches!(st.get_proposal(77), Some(GovProposalObject { version: 1, .. })),
        "failed cross-domain task update must preserve the original proposal slot"
    );
    assert_eq!(st.get_task(77), None);
}

#[test]
fn update_proposal_rejects_cross_domain_object_slot_even_when_version_matches() {
    let mut st = StateStore::new();
    let task_ref = st
        .put_task_new(TaskObject {
            task_id: 88,
            creator: "alice".into(),
            bounty: 13,
            status: TaskStatus::Open,
            proof_type: Default::default(),
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
        })
        .expect("task insert should succeed");

    let err = st
        .update_proposal(
            task_ref,
            GovProposalObject {
                proposal_id: 88,
                title: "wrong domain".into(),
                proposer: "mallory".into(),
                status: GovProposalStatus::Voting,
                version: 999,
            },
        )
        .expect_err("proposal update must fail closed when the slot currently holds a task");

    assert!(err.contains("object type mismatch"));
    assert!(
        matches!(st.get_task(88), Some(TaskObject { version: 1, .. })),
        "failed cross-domain proposal update must preserve the original task slot"
    );
    assert_eq!(st.get_proposal(88), None);
}

#[test]
fn transition_proposal_status_rejects_cross_domain_task_slot_even_when_version_matches() {
    let mut st = StateStore::new();
    let task_ref = st
        .put_task_new(TaskObject {
            task_id: 91,
            creator: "alice".into(),
            bounty: 21,
            status: TaskStatus::Assigned,
            proof_type: Default::default(),
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
        })
        .expect("task insert should succeed");

    let err = st
        .transition_proposal_status(task_ref, GovProposalStatus::Voting)
        .expect_err("proposal transition must fail closed when the slot currently holds a task");

    assert!(err.contains("object type mismatch"));
    assert!(
        matches!(st.get_task(91), Some(TaskObject { version: 1, status: TaskStatus::Assigned, .. })),
        "failed cross-domain proposal transition must preserve the original task slot"
    );
    assert_eq!(st.get_proposal(91), None);
}

#[test]
fn governance_reads_fail_closed_on_key_id_index_drift() {
    let mut st = StateStore::new();
    let gov_ref = st
        .set_gov_param(0, 111, "max_block_ms".into(), "500".into())
        .expect("governance param insertion should succeed");
    let original = st
        .get_param(gov_ref.id)
        .expect("stored governance param should exist");

    st.objects.insert(
        gov_ref.id,
        VersionedObject {
            version: gov_ref.version,
            value: ObjectValue::GovParam(GovParamObject {
                key_id: gov_ref.id + 1,
                ..original
            }),
        },
    );

    assert_eq!(
        st.gov_param_u64("max_block_ms"),
        None,
        "governance reads must fail closed when registry id and stored key_id drift"
    );
    assert_eq!(
        st.gov_param_ref_for_key("max_block_ms"),
        None,
        "governance ref lookup must reject mismatched embedded key ids"
    );
}

#[test]
fn resolve_approval_requires_two_distinct_approvers_before_ready() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first, "single approver must not finalize resolve approval");
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("same approver must not satisfy multi-party confirmation");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(
        second,
        "second distinct approver must finalize resolve approval"
    );
    assert_eq!(st.pending_resolve_approval(42), Some((true, 2)));

    st.clear_pending_resolve_approval(42);
    assert!(st.pending_resolve_approval(42).is_none());
}

#[test]
fn resolve_approval_rejects_decision_mismatch_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(7, 1, false, "authority-a", "authority-a,authority-b")
        .expect("initial non-slash approval should stage");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(7), Some((false, 1)));

    let mismatch = st
        .stage_or_confirm_resolve_approval(7, 1, true, "authority-b", "authority-a,authority-b")
        .expect_err("mismatched slash decision must fail closed");
    assert!(mismatch.contains("decision mismatch"));
    assert_eq!(
        st.pending_resolve_approval(7),
        Some((false, 1)),
        "decision mismatch must not mutate staged confirmation"
    );
}

#[test]
fn resolve_approval_rejects_post_quorum_replay_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);

    let second = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(second);
    assert_eq!(st.pending_resolve_approval(88), Some((true, 2)));

    let replay_err = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-c", "authority-a,authority-b")
        .expect_err("post-quorum replay must be rejected");
    assert!(
        replay_err.contains("already finalized")
            || replay_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(88),
        Some((true, 2)),
        "post-quorum replay must not mutate confirmation state"
    );
}

#[test]
fn resolve_approval_rejects_case_drift_duplicate_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(77, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(77), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(77, 1, true, "Authority-A", "authority-a,authority-b")
        .expect_err("case-drift duplicate approver must be rejected");
    assert!(
        dup_err.contains("distinct approver") || dup_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(77),
        Some((true, 1)),
        "case-drift duplicate must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_whitespace_drift_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(78, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(78), Some((true, 1)));

    let whitespace_err = st
        .stage_or_confirm_resolve_approval(78, 1, true, " authority-a ", "authority-a,authority-b")
        .expect_err("whitespace-drift approver must be rejected");
    assert!(whitespace_err.contains("must not contain whitespace"));
    assert_eq!(
        st.pending_resolve_approval(78),
        Some((true, 1)),
        "whitespace-drift approver must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_multiactor_delimited_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(79, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(79), Some((true, 1)));

    for bad_actor in ["authority-a,authority-b", "authority-a;authority-b"] {
        let err = st
            .stage_or_confirm_resolve_approval(79, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("delimited approver id must be rejected");
        assert!(err.contains("single canonical actor id"));
        assert_eq!(
            st.pending_resolve_approval(79),
            Some((true, 1)),
            "invalid approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn resolve_approval_rejects_system_or_treasury_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(80, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(80), Some((true, 1)));

    for bad_actor in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "System",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Forfeits",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(80, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("system/treasury approver must be rejected");
        assert!(err.contains("explicit non-system authority"));
        assert_eq!(
            st.pending_resolve_approval(80),
            Some((true, 1)),
            "reserved approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn restore_task_rejects_missing_metadata_for_challenged_task() {
    let mut st = StateStore::new();

    st.restore_task(
        9_929,
        Some(TaskObject {
            task_id: 9_929,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
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
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    assert!(
        st.get_task(9_929).is_none(),
        "restore_task must fail closed when a challenged snapshot omits audit/proof metadata"
    );
}

#[test]
fn restore_pending_resolve_snapshot_rejects_missing_task_metadata_for_challenged_task() {
    let mut st = StateStore::new();
    st.set_gov_param(98_240, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_260, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");

    st.restore_task(
        9_930,
        Some(TaskObject {
            task_id: 9_930,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
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
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_930,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-b".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_930), None);
    assert_eq!(st.pending_resolve_first_approver(9_930), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_930), None);
}

#[test]
fn restore_pending_resolve_snapshot_rejects_missing_challenge_timing_metadata() {
    let mut st = StateStore::new();
    st.set_gov_param(98_240, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_260, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");

    st.restore_task(
        9_931,
        Some(TaskObject {
            task_id: 9_931,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: Some(TaskMetadata {
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "inference".into(),
                    metering_schema: "metering.v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "receipt-paused".into(),
                    prompt_tokens: 0,
                    generated_tokens: 0,
                    decode_steps: 0,
                    kv_bytes_moved: 0,
                    normalized_work_units: 1,
                    prompt_token_weight: 1,
                    generated_token_weight: 1,
                    decode_step_weight: 1,
                    kv_byte_weight: 1,
                    min_accept_work_units: 0,
                    challenge_success_bounty_base: 0,
                    challenge_success_bounty_per_work_unit_num: 0,
                    challenge_success_bounty_per_work_unit_den: 1,
                    worker_completion_bonus_per_work_unit_num: 0,
                    worker_completion_bonus_per_work_unit_den: 1,
                    worker_slash_rebate_per_work_unit_num: 0,
                    worker_slash_rebate_per_work_unit_den: 1,
                }),
                ..Default::default()
                            settlement: None,
            }),
            worker: Some("worker-paused".into()),
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
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-b".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_931), None);
    assert_eq!(st.pending_resolve_first_approver(9_931), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_931), None);
}

#[test]
fn restore_pending_resolve_snapshot_rejects_zeroed_resolve_deadline_retention_metadata() {
    let mut st = StateStore::new();
    st.set_gov_param(98_240, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_260, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");

    st.restore_task(
        9_931,
        Some(TaskObject {
            task_id: 9_931,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: Some(TaskMetadata {
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "inference".into(),
                    metering_schema: "metering.v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "receipt-paused".into(),
                    prompt_tokens: 0,
                    generated_tokens: 0,
                    decode_steps: 0,
                    kv_bytes_moved: 0,
                    normalized_work_units: 1,
                    prompt_token_weight: 1,
                    generated_token_weight: 1,
                    decode_step_weight: 1,
                    kv_byte_weight: 1,
                    min_accept_work_units: 0,
                    challenge_success_bounty_base: 0,
                    challenge_success_bounty_per_work_unit_num: 0,
                    challenge_success_bounty_per_work_unit_den: 1,
                    worker_completion_bonus_per_work_unit_num: 0,
                    worker_completion_bonus_per_work_unit_den: 1,
                    worker_slash_rebate_per_work_unit_num: 0,
                    worker_slash_rebate_per_work_unit_den: 1,
                }),
                ..Default::default()
                            settlement: None,
            }),
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: Some(98_271),
            challenge_window_blocks_snapshot: Some(11),
            challenged_at_height: Some(98_260),
            resolve_deadline_height: Some(0),
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-b".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_931), None);
    assert_eq!(st.pending_resolve_first_approver(9_931), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_931), None);
}

#[test]
fn restore_pending_resolve_snapshot_rejects_control_char_proof_metadata() {
    let mut st = StateStore::new();
    st.set_gov_param(98_240, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(98_260, 7_310, "resolve_authority".into(), "authority-a,authority-b".into())
        .expect("bootstrap resolve_authority should apply after timelock");

    st.restore_task(
        9_932,
        Some(TaskObject {
            task_id: 9_932,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: Some(TaskMetadata {
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "inference".into(),
                    metering_schema: "metering.v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "receipt\npaused".into(),
                    prompt_tokens: 0,
                    generated_tokens: 0,
                    decode_steps: 0,
                    kv_bytes_moved: 0,
                    normalized_work_units: 1,
                    prompt_token_weight: 1,
                    generated_token_weight: 1,
                    decode_step_weight: 1,
                    kv_byte_weight: 1,
                    min_accept_work_units: 0,
                    challenge_success_bounty_base: 0,
                    challenge_success_bounty_per_work_unit_num: 0,
                    challenge_success_bounty_per_work_unit_den: 1,
                    worker_completion_bonus_per_work_unit_num: 0,
                    worker_completion_bonus_per_work_unit_den: 1,
                    worker_slash_rebate_per_work_unit_num: 0,
                    worker_slash_rebate_per_work_unit_den: 1,
                }),
                ..Default::default()
                            settlement: None,
            }),
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: Some(98_271),
            challenge_window_blocks_snapshot: Some(11),
            challenged_at_height: Some(98_260),
            resolve_deadline_height: Some(98_282),
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_932,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-b".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_932), None);
}

#[test]
fn resolve_approval_rejects_noncanonical_authority_set_without_mutation() {
    let mut st = StateStore::new();

    for malformed_set in [
        "authority-a",
        "authority-a,",
        "authority-a, authority-b",
        "authority-a;authority-b",
        "authority-a,AUTHORITY-A",
        "authority-a,system",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(8_882, 1, true, "authority-a", malformed_set)
            .expect_err("non-canonical authority set must fail closed");
        assert!(
            err.contains("authority set"),
            "unexpected error for malformed set {malformed_set}: {err}"
        );
        assert_eq!(
            st.pending_resolve_approval(8_882),
            None,
            "malformed authority set must not stage pending approvals"
        );
    }
}

#[test]
fn resolve_approval_clears_stale_stage_on_task_version_change() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(82, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(82), Some((true, 1)));

    let version_err = st
        .stage_or_confirm_resolve_approval(82, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task version change must fail closed and clear stale stage");
    assert!(version_err.contains("task version changed"));
    assert_eq!(st.pending_resolve_approval(82), None);
    assert_eq!(st.pending_resolve_first_approver(82), None);
}

#[test]
fn resolve_approval_task_version_mismatch_invalidates_cached_state_root() {
    let mut st = StateStore::new();

    st.stage_or_confirm_resolve_approval(8_283, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");

    let root_with_pending = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(8_283, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task-version mismatch should clear staged approval");
    assert!(err.contains("task version changed"));

    let root_after_clear = st.state_root();

    let baseline = StateStore::new().state_root();
    assert_eq!(st.pending_resolve_approval(8_283), None);
    assert_ne!(
        root_with_pending, root_after_clear,
        "clearing stale pending resolve approval must invalidate cached state root"
    );
    assert_eq!(
        root_after_clear, baseline,
        "after stale-stage clear, state root should match an empty store"
    );
}

#[test]
fn resolve_approval_clears_stale_stage_on_authority_set_rotation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(81), Some((true, 1)));

    let rotated_err = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-c", "authority-a,authority-c")
        .expect_err("authority set rotation must fail closed and clear stale stage");
    assert!(rotated_err.contains("authority set changed"));
    assert_eq!(st.pending_resolve_approval(81), None);
    assert_eq!(st.pending_resolve_first_approver(81), None);
}

#[test]
fn resolve_approval_clears_stale_stage_on_authority_set_case_drift() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(8_181), Some((true, 1)));

    let case_drift_err = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "Authority-B", "authority-a,Authority-B")
        .expect_err("authority set case drift must fail closed and clear stale stage");
    assert!(case_drift_err.contains("authority set changed"));
    assert_eq!(st.pending_resolve_approval(8_181), None);
    assert_eq!(st.pending_resolve_first_approver(8_181), None);
}

#[test]
fn governance_minimal_state_machine() {
    let mut st = StateStore::new();
    let p = GovProposalObject {
        proposal_id: 9001,
        title: "update param x".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let r1 = st.put_proposal_new(p).unwrap();

    let r2 = st
        .transition_proposal_status(r1, GovProposalStatus::Voting)
        .unwrap();
    let r3 = st
        .transition_proposal_status(r2, GovProposalStatus::Passed)
        .unwrap();
    let _r4 = st
        .transition_proposal_status(r3, GovProposalStatus::Executed)
        .unwrap();

    let cur = st.get_proposal(9001).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Executed);
}

#[test]
fn governance_invalid_transition_rejected() {
    let mut st = StateStore::new();
    let p = GovProposalObject {
        proposal_id: 9002,
        title: "bad jump".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let r1 = st.put_proposal_new(p).unwrap();
    let err = st
        .transition_proposal_status(r1, GovProposalStatus::Passed)
        .unwrap_err();
    assert!(err.contains("invalid governance transition"));
}

#[test]
fn governance_pause_does_not_bypass_invalid_transition_guards() {
    // Merge-gate guard: emergency pause must not weaken proposal transition checks.
    let mut st = StateStore::new();

    // Enter paused mode through the checked governance path.
    let paused = st
        .set_gov_param(9_200, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(paused, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());

    let proposal = GovProposalObject {
        proposal_id: 9_201,
        title: "paused invalid jump".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let expected = st.put_proposal_new(proposal).unwrap();

    let err = st
        .transition_proposal_status(expected, GovProposalStatus::Passed)
        .unwrap_err();
    assert!(err.contains("invalid governance transition"));

    // Proposal must remain unchanged after failed transition while paused.
    let cur = st.get_proposal(9_201).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Draft);
    assert_eq!(
        cur.version, 1,
        "failed transition while paused must not mutate proposal version"
    );
}

#[test]
fn governance_pause_does_not_block_valid_transition_path() {
    // Merge-gate guard: emergency pause is an execution-risk brake, not a governance
    // proposal lifecycle freeze. Valid state-machine transitions must still work.
    let mut st = StateStore::new();
    st.set_gov_param(9_210, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let proposal = GovProposalObject {
        proposal_id: 9_211,
        title: "paused valid path".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let mut expected = st.put_proposal_new(proposal).unwrap();

    expected = st
        .transition_proposal_status(expected, GovProposalStatus::Voting)
        .expect("Draft->Voting must remain valid while paused");
    expected = st
        .transition_proposal_status(expected, GovProposalStatus::Passed)
        .expect("Voting->Passed must remain valid while paused");
    let _ = st
        .transition_proposal_status(expected, GovProposalStatus::Executed)
        .expect("Passed->Executed must remain valid while paused");

    let cur = st.get_proposal(9_211).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Executed);
}

#[test]
fn governance_terminal_states_are_non_transitional() {
    let mut st = StateStore::new();

    let executed = GovProposalObject {
        proposal_id: 9003,
        title: "already executed".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Executed,
        version: 1,
    };
    let executed_ref = st.put_proposal_new(executed).unwrap();
    let err_executed = st
        .transition_proposal_status(executed_ref, GovProposalStatus::Voting)
        .unwrap_err();
    assert!(err_executed.contains("invalid governance transition"));

    let rejected = GovProposalObject {
        proposal_id: 9004,
        title: "already rejected".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Rejected,
        version: 1,
    };
    let rejected_ref = st.put_proposal_new(rejected).unwrap();
    let err_rejected = st
        .transition_proposal_status(rejected_ref, GovProposalStatus::Voting)
        .unwrap_err();
    assert!(err_rejected.contains("invalid governance transition"));
}

#[test]
fn governance_transition_matrix_remains_strict_and_exhaustive() {
    fn expected_transition_allowed(from: GovProposalStatus, to: GovProposalStatus) -> bool {
        // Exhaustive merge-gate guard: adding/changing statuses requires updating this matrix.
        match (from, to) {
            (GovProposalStatus::Draft, GovProposalStatus::Voting)
            | (GovProposalStatus::Voting, GovProposalStatus::Passed)
            | (GovProposalStatus::Voting, GovProposalStatus::Rejected)
            | (GovProposalStatus::Passed, GovProposalStatus::Executed) => true,
            (GovProposalStatus::Draft, _)
            | (GovProposalStatus::Voting, _)
            | (GovProposalStatus::Passed, _)
            | (GovProposalStatus::Rejected, _)
            | (GovProposalStatus::Executed, _) => false,
        }
    }

    let statuses = [
        GovProposalStatus::Draft,
        GovProposalStatus::Voting,
        GovProposalStatus::Passed,
        GovProposalStatus::Rejected,
        GovProposalStatus::Executed,
    ];

    for &from in &statuses {
        for &to in &statuses {
            let mut st = StateStore::new();
            let proposal_id = 95_000 + (from as u64) * 10 + (to as u64);
            let proposal = GovProposalObject {
                proposal_id,
                title: "matrix".into(),
                proposer: "merge-gate".into(),
                status: from,
                version: 1,
            };
            let expected = st.put_proposal_new(proposal).unwrap();
            let outcome = st.transition_proposal_status(expected, to);

            if expected_transition_allowed(from, to) {
                assert!(
                    outcome.is_ok(),
                    "expected transition to succeed for {:?}->{:?}",
                    from,
                    to
                );
            } else {
                let err = outcome.unwrap_err();
                assert!(
                    err.contains("invalid governance transition"),
                    "expected invalid transition for {:?}->{:?}, got: {}",
                    from,
                    to,
                    err
                );
            }
        }
    }
}

#[test]
fn governance_param_whitelist_enforced() {
    let mut st = StateStore::new();
    let ok = st
        .set_gov_param_unchecked(7001, "max_block_ms".into(), "10".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let cur = st.get_param(7001).unwrap();
    assert_eq!(cur.key, "max_block_ms");
    assert_eq!(cur.value, "10");

    let bounty_ok = st
        .set_gov_param_unchecked(7003, "challenge_success_bounty".into(), "5".into())
        .unwrap();
    assert_eq!(bounty_ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7002, "forbidden_key".into(), "1".into())
        .unwrap_err();
    assert!(err.contains("not allowed"));
}

#[test]
fn governance_param_schema_rejects_invalid_u64_values() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(7101, "max_block_ms".into(), "abc".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "32".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7102, "challenge_window_blocks".into(), "99".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7103, "min_worker_stake".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7104, "challenge_min_bond".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7105, "challenge_success_bounty".into(), "-1".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(
            7105,
            "challenge_min_bond_bounty_bps".into(),
            "100001".into(),
        )
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(
            7106,
            "challenge_min_bond_worker_stake_bps".into(),
            "0".into(),
        )
        .unwrap();
    assert_eq!(ok.version, 1);
}

#[test]
fn governance_key_id_collision_with_non_param_rejected() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 7400,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
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
    st.put_task_new(t).unwrap();

    let err = st
        .set_gov_param_unchecked(7400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err.contains("not GovParam"));

    let p = GovProposalObject {
        proposal_id: 7405,
        title: "change block time".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    st.put_proposal_new(p).unwrap();

    let err = st
        .set_gov_param_unchecked(7405, "max_block_ms".into(), "20".into())
        .unwrap_err();
    assert!(err.contains("not GovParam"));
}

#[test]
fn governance_non_sensitive_failed_apply_does_not_scrub_pending_queue() {
    // Merge-gate guard: failed writes must be side-effect free for unrelated
    // pending governance state (except explicit Cancel unsupported path).
    let mut st = StateStore::new();

    st.pending_gov_updates.insert(
        "max_block_ms".into(),
        PendingGovParamUpdate {
            key_id: 7_400,
            key: "max_block_ms".into(),
            value: "15".into(),
            activate_at_height: 77_700,
        },
    );

    let task = TaskObject {
        task_id: 7_400,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
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
    st.put_task_new(task).unwrap();

    let err_unchecked = st
        .set_gov_param_unchecked(7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_unchecked.contains("not GovParam"));
    assert!(
        st.pending_gov_update("max_block_ms").is_some(),
        "failed unchecked apply must not scrub pending queue"
    );

    let err_checked = st
        .set_gov_param(77_701, 7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_checked.contains("not GovParam"));

    let pending = st
        .pending_gov_update("max_block_ms")
        .expect("failed checked apply must not scrub pending queue");
    assert_eq!(pending.key_id, 7_400);
    assert_eq!(pending.activate_at_height, 77_700);
}

#[test]
fn governance_same_key_different_id_shadow_attempt_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7401, "max_block_ms".into(), "15".into())
        .unwrap();

    let err = st
        .set_gov_param_unchecked(7402, "max_block_ms".into(), "20".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));
}

#[test]
fn governance_readers_use_deterministic_current_value() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "15".into())
        .unwrap();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "20".into())
        .unwrap();

    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_u128("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_string("max_block_ms"), Some("20".into()));
}

#[test]
fn governance_sensitive_update_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7300, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(1_000, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 1_020);

    let err = st
        .set_gov_param(1_019, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));
}

#[test]
fn governance_sensitive_update_accepted_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7301, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let _ = st
        .set_gov_param(2_000, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_020, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();
    match applied {
        GovParamUpdateOutcome::Applied(r) => assert!(r.version >= 2),
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected applied"),
        GovParamUpdateOutcome::Cancelled => panic!("expected applied"),
    }

    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(120));
    assert!(st.pending_gov_update("challenge_min_bond").is_none());
}

#[test]
fn governance_sensitive_noop_update_is_immediate_without_timelock() {
    let mut st = StateStore::new();
    let seeded = st
        .set_gov_param_unchecked(7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_500, 7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    match applied {
        GovParamUpdateOutcome::Applied(r) => {
            assert_eq!(r.id, seeded.id);
            assert_eq!(r.version, seeded.version);
        }
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected immediate no-op apply"),
        GovParamUpdateOutcome::Cancelled => panic!("expected immediate no-op apply"),
    }

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}

#[test]
fn governance_resolve_authority_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7310,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            10_000,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 10_020);

    let err = st
        .set_gov_param(
            10_019,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err.contains("timelock active"));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn governance_resolve_authority_applied_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7311,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let _ = st
        .set_gov_param(
            11_000,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();

    let applied = st
        .set_gov_param(
            11_020,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_non_canonical_value_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            " resolver-v2 ".into(),
        )
        .unwrap_err();
    assert!(err.contains("whitespace") || err.contains("canonical"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_forbidden_separator_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7313,
            "resolve_authority".into(),
            "resolver-a，resolver-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("separator") || err.contains("ASCII ','"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_non_ascii_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7314,
            "resolve_authority".into(),
            "resolver-a,resolvér-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("ASCII-only") || err.contains("whitespace") || err.contains("separator"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_single_member_update_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7315,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_500,
            7315,
            "resolve_authority".into(),
            "resolver-v3".into(),
        )
        .expect_err("singleton resolve_authority update must be rejected");
    assert!(err.contains("at least two members"), "{err}");

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_pending_mismatch_behaves_like_sensitive_keys() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 12_020
        }
    ));

    let err_value = st
        .set_gov_param(
            12_005,
            7312,
            "resolve_authority".into(),
            "resolver-v5,resolver-v6".into(),
        )
        .unwrap_err();
    assert!(err_value.contains("pending governance update exists"));

    let err_id = st
        .set_gov_param(
            12_005,
            9999,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err_id.contains("governance key id mismatch for resolve_authority"));

    let pending = st.pending_gov_update("resolve_authority").unwrap();
    assert_eq!(pending.key_id, 7312);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 12_020);
}

#[test]
fn governance_resolve_authority_unchecked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial unchecked resolve_authority write should succeed");

    let err = st
        .set_gov_param_unchecked(
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("unchecked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn governance_resolve_authority_unchecked_path_rejects_reserved_emergency_pause_key_id_alias() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(
            7_999,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect_err("reserved emergency_pause key id must stay pinned on unchecked path");

    assert!(
        err.contains("governance key id mismatch for id 7999: expected_key=emergency_pause, attempted_key=resolve_authority"),
        "{err}"
    );
    assert_eq!(st.gov_param_string("resolve_authority"), None);
    assert!(!st.is_emergency_paused());
}

#[test]
fn governance_resolve_authority_checked_path_rejects_key_id_shadowing_without_state_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let err = st
        .set_gov_param(
            14_000,
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("checked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(
        st.pending_gov_update("resolve_authority").is_none(),
        "rejected key-id shadowing must not enqueue pending updates"
    );
}

#[test]
fn governance_resolve_authority_cancel_wrong_key_id_preserves_pending_update() {
    // Merge-gate guard: cancel for a sensitive resolve_authority timelock must reject
    // key-id drift before any pending queue mutation.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let scheduled = st
        .set_gov_param(
            14_500,
            7314,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority update should schedule");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 14_520
        }
    ));

    let err = st
        .set_gov_param_with_action(
            14_505,
            9001,
            "resolve_authority".into(),
            "ignored-on-cancel".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel with wrong key id must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("wrong-key cancel must not clear pending resolve_authority update");
    assert_eq!(pending.key_id, 7314);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 14_520);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn emergency_pause_does_not_mutate_pending_resolve_authority_update() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            13_000,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 13_020
        }
    ));

    st.set_gov_param(13_001, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    st.set_gov_param(13_002, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause toggle must apply immediately");

    assert!(!st.is_emergency_paused());
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should survive pause toggles");
    assert_eq!(pending.key_id, 7313);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 13_020);

    let applied = st
        .set_gov_param(
            13_020,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority should still activate at original timelock height");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_sensitive_pending_replace_before_activation_resets_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7320, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let first = st
        .set_gov_param(20_000, 7320, "challenge_window_blocks".into(), "110".into())
        .unwrap();
    assert!(matches!(
        first,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_020
        }
    ));

    let replaced = st
        .set_gov_param_with_action(
            20_005,
            7320,
            "challenge_window_blocks".into(),
            "120".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(
        replaced,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_025
        }
    ));

    let pending = st.pending_gov_update("challenge_window_blocks").unwrap();
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 20_025);

    let err = st
        .set_gov_param(20_020, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(20_025, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}

#[test]
fn governance_sensitive_pending_cancel_before_activation_removes_pending() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7321, "challenge_min_bond".into(), "100".into())
        .unwrap();

    st.set_gov_param(21_000, 7321, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let cancelled = st
        .set_gov_param_with_action(
            21_005,
            7321,
            "challenge_min_bond".into(),
            "".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap();
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}

#[test]
fn governance_non_sensitive_cancel_path_still_enforces_validator_registry_guard() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            21_005,
            7_999,
            "emergency_pause".into(),
            "not-a-bool".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("non-sensitive cancel path must still fail closed before mutation");
    assert!(
        err.contains("governance cancel not supported for non-sensitive key emergency_pause"),
        "unexpected cancel-path error: {err}"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn governance_sensitive_apply_without_pending_is_unchanged() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7322, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(22_000, 7322, "challenge_min_bond".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 22_020
        }
    ));
}

#[test]
fn governance_sensitive_rate_limit_still_enforced_after_replace() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7323, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    st.set_gov_param(23_000, 7323, "challenge_window_blocks".into(), "120".into())
        .unwrap();

    st.set_gov_param_with_action(
        23_005,
        7323,
        "challenge_window_blocks".into(),
        "119".into(),
        GovPendingUpdateAction::Replace,
    )
    .unwrap();

    let err = st
        .set_gov_param_with_action(
            23_006,
            7323,
            "challenge_window_blocks".into(),
            "130".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}

#[test]
fn governance_sensitive_update_excessive_step_change_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7302, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let err = st
        .set_gov_param(3_000, 7302, "challenge_window_blocks".into(), "130".into())
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}

#[test]
fn governance_sensitive_update_bounded_step_change_accepted() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7303, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(4_000, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 4_020
        }
    ));

    let applied = st
        .set_gov_param(4_020, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}

#[test]
fn governance_challenge_success_bounty_is_sensitive_and_timelocked() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7350, "challenge_success_bounty".into(), "1".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(30_000, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 30_020
        }
    ));

    let err = st
        .set_gov_param(30_010, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(30_020, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_success_bounty"), Some(2));
}

#[test]
fn governance_non_sensitive_param_unaffected_by_timelock() {
    let mut st = StateStore::new();
    let r1 = st
        .set_gov_param(5_000, 7304, "max_block_ms".into(), "15".into())
        .unwrap();
    assert!(matches!(r1, GovParamUpdateOutcome::Applied(_)));

    let r2 = st
        .set_gov_param(5_001, 7304, "max_block_ms".into(), "20".into())
        .unwrap();
    assert!(matches!(r2, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert!(st.pending_gov_update("max_block_ms").is_none());
}

#[test]
fn emergency_pause_requires_strict_bool_literal() {
    let mut st = StateStore::new();

    for bad in [
        "TRUE", "False", "1", "yes", " true", "false ", "\ttrue", "\ntrue", "false\n",
    ] {
        let err = st
            .set_gov_param_unchecked(7999, "emergency_pause".into(), bad.into())
            .unwrap_err();
        assert!(err.contains("strict bool"));
    }

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_flag_works() {
    let mut st = StateStore::new();
    assert!(!st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_unchecked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: even unchecked writes must keep emergency_pause pinned to 7999.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param_unchecked(8_000, "emergency_pause".into(), "true".into())
        .expect_err("unchecked non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: emergency_pause must remain pinned to canonical key id.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param(8_050, 8_000, "emergency_pause".into(), "true".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation() {
    // Merge-gate guard: key-id mismatch must fail before value schema parsing,
    // so malformed values cannot alter error semantics.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param(8_051, 8_000, "emergency_pause".into(), "TRUE".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected first");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(
        !err.contains("strict bool"),
        "key-id mismatch path must not leak value-schema errors: {err}"
    );
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_replace_rejects_non_canonical_key_id_without_side_effects() {
    // Merge-gate guard: Replace action must enforce the same canonical key-id pinning.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            8_051,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace with non-canonical emergency_pause key_id must be rejected");

    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_path_is_immediate_and_non_cancellable() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param(8_000, 7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let cancel_err = st
        .set_gov_param_with_action(
            8_001,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    // Failed cancel must be side-effect free on pause state and pending queues.
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let applied_unpause = st
        .set_gov_param(8_002, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(matches!(applied_unpause, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_noop_update_is_idempotent_after_pause() {
    // Merge-gate guard: repeated identical emergency_pause writes should be side-effect free.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(8_010, 7_999, "emergency_pause".into(), "true".into())
        .expect("initial pause=true write must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param(8_011, 7_999, "emergency_pause".into(), "true".into())
        .expect("noop pause=true write must succeed");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(first_ref, second_ref, "noop must not churn object version");
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_replace_noop_is_idempotent() {
    // Merge-gate guard: Replace action on a non-sensitive emergency_pause value should
    // stay immediate and avoid version churn when value is unchanged.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            8_620,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("initial replace pause=true write must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply for non-sensitive replace"),
    };

    let second = st
        .set_gov_param_with_action(
            8_621,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("noop replace pause=true write must succeed");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply for non-sensitive replace"),
    };

    assert_eq!(
        first_ref, second_ref,
        "non-sensitive replace noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_cancel_scrubs_stale_pending_entry_even_when_unsupported() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: non-sensitive emergency_pause should never have
    // timelocked pending state; even unsupported Cancel attempts must scrub stale entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_650,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unsupported cancel must still scrub stale pending emergency_pause entries"
    );
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_skips_value_validation_but_stays_side_effect_free() {
    let mut st = StateStore::new();

    // Merge-gate guard: Cancel keeps parser bypass semantics (no bool validation) but must
    // remain side-effect free beyond stale pending cleanup.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_888,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            7_999,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        !cancel_err.contains("invalid governance value"),
        "cancel path must not attempt value parsing for emergency_pause"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_wrong_key_id_is_rejected_without_scrubbing_state() {
    let mut st = StateStore::new();

    // Merge-gate guard: key_id mismatch must fail before any state cleanup/mutation,
    // even when legacy/corrupt pending emergency_pause data exists.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("expected_id=7999"), "{cancel_err}");

    let pending = st
        .pending_gov_update("emergency_pause")
        .expect("mismatched key_id path must not mutate pending state");
    assert_eq!(pending.key_id, 7_999);
    assert_eq!(pending.activate_at_height, 77_777);
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // but if a stale pending entry exists, checked-path apply must scrub it.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param(8_700, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "stale pending entry must be removed for non-sensitive emergency_pause"
    );
}

#[test]
fn emergency_pause_unchecked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // and unchecked-path writes must still scrub stale pending entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_888,
        },
    );

    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked emergency_pause apply must remove stale pending entry"
    );
}

#[test]
fn emergency_pause_unchecked_noop_is_idempotent_and_clears_stale_pending_entry() {
    let mut st = StateStore::new();

    let first_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("first unchecked pause write must succeed");
    assert!(st.is_emergency_paused());

    // Corrupt/legacy state simulation: stale pending residue must be scrubbed even
    // when the unchecked write is a noop.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_999,
        },
    );

    let second_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked noop pause write must stay idempotent");

    assert_eq!(
        first_ref, second_ref,
        "unchecked noop emergency_pause write must not churn version"
    );
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked noop must still remove stale emergency_pause pending entry"
    );
}

#[test]
fn emergency_pause_does_not_mutate_other_sensitive_pending_updates() {
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(8_600, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 8_620);

    let pause_outcome = st
        .set_gov_param(8_601, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(pause_outcome, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("challenge_min_bond pending update must remain");
    assert_eq!(pending.key_id, 8_500);
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 8_620);
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_remains_immediate_without_pending_state() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_000,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    // Replace action must remain immediate and non-scheduling in both directions.
    let unapplied = st
        .set_gov_param_with_action(
            9_001,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_scrubs_stale_pending_entry() {
    // Merge-gate guard: Replace action must stay on the immediate non-sensitive path,
    // including cleanup of any legacy/corrupt queued emergency_pause timelock entry.
    let mut st = StateStore::new();
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param_with_action(
            9_004,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace action should apply immediately for emergency_pause");

    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_still_enforces_strict_bool_schema() {
    // Merge-gate guard: action variants must not bypass strict bool validation.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            9_005,
            7_999,
            "emergency_pause".into(),
            "TRUE".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace action must reject non-strict bool literal");
    assert!(err.contains("expected strict bool"));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: Replace noop must stay immediate and avoid object-version churn.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_006,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("initial replace pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_007,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "replace noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_action_remains_immediate_without_pending_state() {
    // Merge-gate guard: explicit Enforce action must stay on the immediate path for
    // emergency pause and never route through timelock scheduling.
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_010,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let unapplied = st
        .set_gov_param_with_action(
            9_011,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: explicit Enforce noop must keep immediate semantics and avoid
    // object-version churn for emergency_pause.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_011,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("initial enforce pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_012,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("enforce noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "enforce noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_does_not_bypass_sensitive_timelock_guards() {
    // Merge-gate guard: paused mode must not allow sensitive governance params
    // to skip the timelock state machine.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(9_200, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };

    st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param(9_205, 8_500, "challenge_min_bond".into(), "120".into())
        .expect_err("paused mode must not bypass sensitive timelock");
    assert!(err.contains("timelock active"), "{err}");

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("timelock pending update must remain intact while paused");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(pending.value, "120");
}

#[test]
fn emergency_pause_checked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param(9_100, 7999, "emergency_pause".into(), "true".into())
        .unwrap();

    let err = st
        .set_gov_param(9_101, 8000, "emergency_pause".into(), "false".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));

    // Confirm canonical key id still controls pause state.
    st.set_gov_param(9_102, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn non_sensitive_governance_noop_rejects_mismatched_key_id() {
    // Merge-gate guard: noop/idempotent path must not hide key-id drift for immediate keys.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(9_300, 6_001, "max_block_ms".into(), "500".into())
        .expect("seed max_block_ms must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("max_block_ms must remain immediate"),
    };

    let err = st
        .set_gov_param(9_301, 6_002, "max_block_ms".into(), "500".into())
        .expect_err("mismatched key-id noop must be rejected");
    assert!(err.contains("governance key id mismatch"), "{err}");

    let preserved = st
        .get_param(first_ref.id)
        .expect("canonical max_block_ms entry must remain readable");
    assert_eq!(preserved.key_id, 6_001);
    assert_eq!(preserved.value, "500");
    assert!(st.pending_gov_update("max_block_ms").is_none());
}

#[test]
fn governance_timelock_classification_merge_gate_keeps_emergency_pause_immediate() {
    // Exhaustive merge-gate guard for timelock classification: changing this table means
    // emergency pause semantics changed and tests/rollout should be reviewed explicitly.
    let expected_sensitive = [
        ("challenge_window_blocks", true),
        ("challenge_min_bond", true),
        ("challenge_success_bounty", true),
        ("min_worker_stake", true),
        ("challenge_min_bond_bounty_bps", true),
        ("challenge_min_bond_worker_stake_bps", true),
        ("resolve_authority", true),
        ("emergency_pause", false),
    ];

    let expected_sensitive_count = expected_sensitive.iter().filter(|(_, v)| *v).count();
    assert_eq!(
        GOV_SENSITIVE_KEYS.len(),
        expected_sensitive_count,
        "sensitive-key list changed; update timelock classification merge gate"
    );

    for (key, expected) in expected_sensitive {
        assert!(
            GOV_ALLOWED_KEYS.contains(&key),
            "timelock merge gate contains non-whitelisted key: {}",
            key
        );
        assert_eq!(
            is_sensitive_gov_param(key),
            expected,
            "governance sensitivity drifted for key: {}",
            key
        );
    }

    // Behavioral merge-gate: pause must remain immediate (never timelocked/scheduled).
    let mut st = StateStore::new();
    let outcome = st
        .set_gov_param(96_100, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause update");
    assert!(
        matches!(outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause must apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(st.is_emergency_paused());

    let unpause_outcome = st
        .set_gov_param(96_101, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause update");
    assert!(
        matches!(unpause_outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause=false must also apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn governance_allowed_keys_have_single_explicit_validator_registry() {
    let allowed_unique: std::collections::BTreeSet<&str> =
        GOV_ALLOWED_KEYS.iter().copied().collect();
    let validator_unique: std::collections::BTreeSet<&str> =
        GOV_KEYS_WITH_EXPLICIT_VALIDATORS.iter().copied().collect();

    assert_eq!(
        validator_unique.len(),
        GOV_KEYS_WITH_EXPLICIT_VALIDATORS.len(),
        "GOV_KEYS_WITH_EXPLICIT_VALIDATORS contains duplicate entries"
    );
    assert_eq!(
        allowed_unique, validator_unique,
        "allowed governance keys and explicit validator registry must stay identical"
    );
}

#[test]
fn governance_validator_registry_drift_fails_closed_at_runtime_boundary() {
    let err = validate_gov_param_value("not_whitelisted", "1")
        .expect_err("unknown governance keys must fail closed at the validator boundary");
    assert!(
        err.contains("missing explicit validator registration")
            || err.contains("no explicit validator registered"),
        "unexpected runtime validator drift error: {err}"
    );
}

#[test]
fn governance_allowed_keys_schema_merge_gate_is_explicit() {
    // Exhaustive merge-gate guard for whitelist+schema safety. Any added/changed key
    // must update the source-side invalid-sample registry beside the validators.
    assert_eq!(
        GOV_ALLOWED_KEYS.len(),
        GOV_SCHEMA_INVALID_SAMPLES.len(),
        "governance allowed-key list changed; update source-side schema merge gate"
    );

    let mut st = StateStore::new();
    for (i, (key, bad_value)) in GOV_SCHEMA_INVALID_SAMPLES.iter().enumerate() {
        assert!(
            GOV_ALLOWED_KEYS.contains(key),
            "schema merge gate contains non-whitelisted key: {}",
            key
        );
        let key_id = if *key == "emergency_pause" {
            7_999
        } else {
            96_000 + i as u64
        };
        let err = st
            .set_gov_param_unchecked(key_id, (*key).into(), (*bad_value).into())
            .unwrap_err();
        assert!(
            err.contains("invalid governance value"),
            "expected schema rejection for key={}, got: {}",
            key,
            err
        );
    }
}

#[test]
fn governance_llm_meter_schema_is_explicit_and_fail_closed() {
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(
        97_050,
        "llm_meter_prompt_token_weight".into(),
        "42".into(),
    )
    .expect("llm meter key with explicit validator should be accepted");
    assert_eq!(
        st.gov_param_u64("llm_meter_prompt_token_weight"),
        Some(42)
    );

    let err = st
        .set_gov_param_unchecked(
            97_051,
            "llm_meter_worker_completion_bonus_per_work_unit_den".into(),
            "0".into(),
        )
        .expect_err("denominator zero must fail closed");
    assert!(err.contains("invalid governance value"), "{err}");
}

#[test]
fn governance_resolve_authority_rejects_reserved_or_placeholder_values() {
    let mut st = StateStore::new();

    for (i, bad_value) in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "Governance.Resolve_Authority",
        RESERVED_SYSTEM_AUTHORITY,
        "System",
        "authority,system",
        "governance.emergency_pause",
        "Emergency_Pause",
        "authority,emergency_pause",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Escrow",
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
        "TREASURY.CHALLENGE_FORFEITS",
        WORKER_SLASH_TREASURY_ACCOUNT,
        "Treasury.Worker_Slashes",
        "authority,treasury.challenge_escrow",
        "authority,Treasury.Challenge_Forfeits",
        "authority,treasury.worker_slashes",
        "authority ",
        "authority team",
        "authority\u{3000}team",
        "authority,",
        ",authority",
        "authority,,authority2",
        "authority,authority",
        "authority,Authority",
        "authority, authority2",
        "authority;authority2",
        "authority|authority2",
        "authority,authority2|authority3",
        "authority,authority2;authority3",
        "authority；authority2",
        "authority，authority2",
        "authority、authority2",
        "authority\u{0000}x",
        "authority,\u{0007}authority2",
    ]
    .iter()
    .enumerate()
    {
        let err = st
            .set_gov_param_unchecked(
                97_100 + i as u64,
                "resolve_authority".into(),
                (*bad_value).into(),
            )
            .expect_err("reserved/malformed resolve_authority must be rejected");
        assert!(
            err.contains("invalid governance value for resolve_authority"),
            "unexpected error for value {:?}: {}",
            bad_value,
            err
        );
    }
}

#[test]
fn governance_accepts_comma_separated_resolve_authority_members() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        97_500,
        "resolve_authority".into(),
        "authority,authority2".into(),
    )
    .expect("comma-separated resolve authority members should be accepted");
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority,authority2".to_string())
    );
}

#[test]
fn emergency_pause_toggles_preserve_challenge_escrow_conservation() {
    // Merge-gate guard: emergency pause is a control-plane brake only; it must never
    // mutate custody balances used by challenge escrow accounting.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 1_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 500);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_000, 7_999, "emergency_pause".into(), "true".into())
        .expect("checked pause write should apply immediately");
    st.set_gov_param(98_001, 7_999, "emergency_pause".into(), "false".into())
        .expect("checked unpause write should apply immediately");
    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked pause write should be accepted at canonical key id");

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn governance_keysets_merge_gate_are_unique_and_subset_safe() {
    // Merge-gate: duplicate keys in static tables can silently weaken policy checks.
    let allowed_unique: std::collections::BTreeSet<&str> =
        GOV_ALLOWED_KEYS.iter().copied().collect();
    assert_eq!(
        allowed_unique.len(),
        GOV_ALLOWED_KEYS.len(),
        "GOV_ALLOWED_KEYS contains duplicate entries"
    );

    let sensitive_unique: std::collections::BTreeSet<&str> =
        GOV_SENSITIVE_KEYS.iter().copied().collect();
    assert_eq!(
        sensitive_unique.len(),
        GOV_SENSITIVE_KEYS.len(),
        "GOV_SENSITIVE_KEYS contains duplicate entries"
    );

    for key in &sensitive_unique {
        assert!(
            allowed_unique.contains(key),
            "sensitive key must also be whitelisted: {}",
            key
        );
    }

    assert!(
        !sensitive_unique.contains("emergency_pause"),
        "emergency_pause must remain immediate and never timelocked"
    );
}

#[test]
fn balance_debit_credit_works() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 15);
    assert_eq!(st.balance_of("challenger"), 15);

    st.debit_balance("challenger", 10).unwrap();
    assert_eq!(st.balance_of("challenger"), 5);

    let err = st.debit_balance("challenger", 6).unwrap_err();
    assert!(err.contains("insufficient balance"));

    st.credit_balance("challenger", 7).unwrap();
    assert_eq!(st.balance_of("challenger"), 12);
}

#[test]
fn balance_credit_overflow_rejected() {
    let mut st = StateStore::new();
    st.set_balance("treasury", u128::MAX - 1);

    let err = st.credit_balance("treasury", 2).unwrap_err();
    assert!(err.contains("balance overflow on credit"));
}

#[test]
fn state_root_changes_when_task_security_fields_change() {
    let mut st = StateStore::new();
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };

    st.put_task_new(task.clone()).unwrap();
    let root_before = st.state_root();

    let mut changed = task;
    changed.challenge_bond_forfeited = Some(true);
    let current_ref = st.get_ref(42).unwrap();
    st.update_task(current_ref, changed).unwrap();
    let root_after = st.state_root();

    assert_ne!(root_before, root_after);
}

#[test]
fn state_root_changes_when_pending_resolve_first_approver_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(500, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(500, 1, true, "authority-b", "authority-a,authority-b")
        .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve first approver must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_task_version_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(501, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(501, 2, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve task version snapshot must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_authority_set_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(501, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(
        501,
        1,
        true,
        "authority-a",
        "authority-a,authority-b,authority-c",
    )
    .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve authority set must contribute to state root"
    );
}

#[test]
fn pending_resolve_restore_canonicalizes_authority_metadata_for_state_root() {
    let mut staged = StateStore::new();
    staged
        .stage_or_confirm_resolve_approval(
            5_200,
            7,
            true,
            "Authority-A",
            "Authority-B,Authority-A",
        )
        .unwrap();

    let mut restored = StateStore::new();
    restored.restore_pending_resolve_approval(
        5_200,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(
        staged.state_root(),
        restored.state_root(),
        "state_root should ignore authority-set ordering and approver casing noise for equivalent pending resolve snapshots"
    );
}

#[test]
fn wal_checkpoint_verification_picks_latest_valid() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
}

#[test]
fn wal_checkpoint_verification_falls_back_on_chain_break() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some("wrong-prev".into()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
}

#[test]
fn wal_checkpoint_verification_rejects_metadata_only_chain_starting_above_genesis() {
    let e10 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "p10".into(),
        committed: true,
        state_root_hex: "r10".into(),
        prev_hash_hex: None,
    };

    let checkpoints = vec![CheckpointMeta {
        height: 10,
        state_root_hex: "r10".into(),
        wal_entry_hash_hex: e10.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e10]).unwrap();
    assert!(
        got.is_none(),
        "restart recovery must fail closed for metadata-only WAL chains that start above genesis height"
    );
}

#[test]
fn wal_checkpoint_verification_falls_back_on_non_monotonic_height() {
    let e1 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        // Repeated height must terminate verification.
        height: 10,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 10,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 10,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_falls_back_on_height_gap() {
    let e1 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        // Missing height 11 must terminate verification fail-closed.
        height: 12,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 10,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 12,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 10);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_is_height_ordered_even_if_checkpoint_list_is_not() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1),
    };
    let h2 = e2.content_hash_hex();

    // Intentionally unsorted input: height 2 checkpoint appears first.
    let checkpoints = vec![
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
    assert_eq!(got.state_root_hex, "r2");
}

#[test]
fn wal_checkpoint_verification_stops_before_uncommitted_tail() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: false,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_fails_closed_on_ambiguous_metadata_at_same_height() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "tampered-root".into(),
            wal_entry_hash_hex: "tampered-hash".into(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_fails_closed_on_incomplete_checkpoint_metadata_at_same_height() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: String::new(),
            wal_entry_hash_hex: "missing-root".into(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_fails_closed_on_whitespace_only_metadata_at_same_height() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "   \n\t  ".into(),
            wal_entry_hash_hex: "present-but-blank".into(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_fails_closed_on_non_canonical_checkpoint_metadata_at_same_height() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: " r2".into(),
            wal_entry_hash_hex: "tampered-hash".into(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_fails_closed_when_checkpoint_metadata_exists_but_does_not_match_committed_wal_entry() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();
    let e3 = WalMeta {
        height: 3,
        round: 0,
        proposal_hash: "p3".into(),
        committed: true,
        state_root_hex: "r3".into(),
        prev_hash_hex: Some(h2),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "tampered-root".into(),
            wal_entry_hash_hex: "tampered-hash".into(),
        },
        CheckpointMeta {
            height: 3,
            state_root_hex: "r3".into(),
            wal_entry_hash_hex: e3.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2, e3])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_content_hash_length_frames_variable_metadata_fields() {
    let a = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "ab".into(),
        committed: true,
        state_root_hex: "c".into(),
        prev_hash_hex: Some("def".into()),
    };
    let b = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "a".into(),
        committed: true,
        state_root_hex: "bc".into(),
        prev_hash_hex: Some("def".into()),
    };

    assert_ne!(
        a.content_hash_hex(),
        b.content_hash_hex(),
        "wal content hash must length-frame proposal and state-root metadata so proof material cannot collide across field boundaries"
    );
}

#[test]
fn policy_tick_triggers_on_interval_and_updates_monetary_state() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_001,
        "monetary_policy_tick_interval_blocks".into(),
        "3".into(),
    )
    .expect("set interval");
    st.set_gov_param_unchecked(
        9_002,
        "monetary_policy_tick_cooldown_blocks".into(),
        "3".into(),
    )
    .expect("set cooldown");
    st.set_gov_param_unchecked(9_003, "monetary_base_issuance_per_tick".into(), "15".into())
        .expect("set issuance");
    st.set_gov_param_unchecked(9_004, "monetary_base_burn_per_tick".into(), "4".into())
        .expect("set burn");

    assert!(st.policy_tick(2).is_none());
    let e1 = st.policy_tick(3).expect("tick at h=3");
    assert_eq!(e1.net_delta, 11);
    assert_eq!(e1.tick_count, 1);
    assert_eq!(e1.block_height, 3);
    assert_eq!(e1.cooldown_blocks, 3);
    assert_eq!(e1.interval_param_version, 1);
    assert_eq!(e1.cooldown_param_version, 1);
    assert!(
        st.policy_tick(3).is_none(),
        "same height must be idempotent"
    );

    let e2 = st.policy_tick(6).expect("tick at h=6");
    assert_eq!(e2.tick_count, 2);
    assert_eq!(e2.total_minted, 30);
    assert_eq!(e2.total_burned, 8);
    assert_eq!(e2.net_issuance, 22);
}

#[test]
fn governance_param_schema_rejects_invalid_monetary_policy_bounds() {
    let mut st = StateStore::new();
    let err_interval = st
        .set_gov_param_unchecked(
            9_010,
            "monetary_policy_tick_interval_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_interval.contains("out of range"));

    let err_cooldown = st
        .set_gov_param_unchecked(
            9_011,
            "monetary_policy_tick_cooldown_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_cooldown.contains("out of range"));

    let err_issuance = st
        .set_gov_param_unchecked(
            9_012,
            "monetary_base_issuance_per_tick".into(),
            "1000000000001".into(),
        )
        .unwrap_err();
    assert!(err_issuance.contains("out of range"));

    let err_burn = st
        .set_gov_param_unchecked(9_013, "monetary_base_burn_per_tick".into(), "-1".into())
        .unwrap_err();
    assert!(err_burn.contains("expected u64"));
}

#[test]
fn policy_tick_fail_closed_when_monetary_params_incomplete() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_020,
        "monetary_policy_tick_interval_blocks".into(),
        "2".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_021, "monetary_base_issuance_per_tick".into(), "1".into())
        .unwrap();
    st.set_gov_param_unchecked(9_022, "monetary_base_burn_per_tick".into(), "0".into())
        .unwrap();

    assert!(!st.should_trigger_policy_tick(2));
    assert!(st.policy_tick(2).is_none());
    assert_eq!(st.monetary_state().tick_count, 0);
}

#[test]
fn policy_tick_cooldown_throttles_repeated_schedule_points() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_030,
        "monetary_policy_tick_interval_blocks".into(),
        "2".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(
        9_031,
        "monetary_policy_tick_cooldown_blocks".into(),
        "4".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_032, "monetary_base_issuance_per_tick".into(), "5".into())
        .unwrap();
    st.set_gov_param_unchecked(9_033, "monetary_base_burn_per_tick".into(), "1".into())
        .unwrap();

    assert!(st.policy_tick(2).is_some());
    assert!(st.policy_tick(4).is_none(), "cooldown should block h=4");
    assert!(st.policy_tick(6).is_some(), "cooldown should allow h=6");
}

#[test]
fn restore_pending_gov_update_unknown_key_fails_closed_without_materializing_queue_entry() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "totally_unknown_key",
        Some(PendingGovParamUpdate {
            key_id: 117,
            key: "totally_unknown_key".into(),
            value: "120".into(),
            activate_at_height: 330,
        }),
    );

    assert!(
        state.pending_gov_update("totally_unknown_key").is_none(),
        "restore_pending_gov_update must fail closed for non-whitelisted governance keys"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "unknown pending governance keys must not perturb the deterministic state root"
    );
}

#[test]
fn restore_pending_gov_update_non_sensitive_key_fails_closed_without_aliasing_immediate_param() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: 118,
            key: "max_block_ms".into(),
            value: "450".into(),
            activate_at_height: 340,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "restore_pending_gov_update must fail closed for non-sensitive immediate governance keys"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "non-sensitive governance keys must not be restorable into the pending timelock queue"
    );
}

#[test]
fn restore_pending_gov_update_noncanonical_snapshot_key_fails_closed_without_aliasing_pending_slot() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 7_310,
            key: " resolve_authority".into(),
            value: "authority-a,authority-b".into(),
            activate_at_height: 340,
        }),
    );

    assert!(
        state.pending_gov_update("resolve_authority").is_none(),
        "restore_pending_gov_update must fail closed when the snapshot key spelling is non-canonical"
    );
    assert!(
        state.pending_gov_update(" resolve_authority").is_none(),
        "non-canonical snapshot keys must not materialize an aliased pending governance slot"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "non-canonical snapshot keys must not perturb the deterministic state root"
    );
}

#[test]
fn restore_pending_gov_update_foreign_key_id_collision_fails_closed() {
    let mut state = StateStore::new();
    state
        .set_gov_param_unchecked(113, "challenge_min_bond".into(), "5000".into())
        .expect("canonical challenge_min_bond write should succeed");
    let root_with_canonical_param = state.state_root();

    state.restore_pending_gov_update(
        "challenge_success_bounty",
        Some(PendingGovParamUpdate {
            key_id: 113,
            key: "challenge_success_bounty".into(),
            value: "6000".into(),
            activate_at_height: 350,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_success_bounty").is_none(),
        "restore_pending_gov_update must fail closed when a snapshot reuses another governance key's canonical id"
    );
    assert_eq!(
        state.gov_param_string("challenge_min_bond"),
        Some("5000".into()),
        "foreign key-id collision must not disturb the existing canonical governance registration"
    );
    assert_eq!(
        state.state_root(),
        root_with_canonical_param,
        "foreign key-id collision must leave the deterministic root unchanged"
    );
}

#[test]
fn restore_pending_gov_update_live_object_embedded_key_id_drift_fails_closed() {
    let mut state = StateStore::new();
    let applied = state
        .set_gov_param_unchecked(7_201, "challenge_min_bond".into(), "5000".into())
        .expect("canonical challenge_min_bond write should succeed");
    let canonical = state
        .get_param(applied.id)
        .expect("canonical challenge_min_bond object should exist");

    state.objects.insert(
        applied.id,
        VersionedObject {
            version: applied.version,
            value: ObjectValue::GovParam(GovParamObject {
                key_id: applied.id + 1,
                ..canonical
            }),
        },
    );
    let root_with_corrupt_live_object = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".into(),
            value: "6000".into(),
            activate_at_height: 1_020,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restore_pending_gov_update must fail closed when the live GovParam object embeds a drifted key_id"
    );
    assert_eq!(
        state.state_root(),
        root_with_corrupt_live_object,
        "failed restore must not mutate state beyond preserving the existing corrupt live-object snapshot"
    );
}

#[test]
fn restore_pending_gov_update_same_key_id_drift_fails_closed() {
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".into(),
            value: "6000".into(),
            activate_at_height: 1_020,
        }),
    );
    let root_with_canonical_pending = state.state_root();
    assert!(state.pending_gov_update("challenge_min_bond").is_some());

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "challenge_min_bond".into(),
            value: "6000".into(),
            activate_at_height: 1_020,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restore_pending_gov_update must fail closed when the same pending governance key reappears under a different key_id"
    );
    assert_ne!(
        state.state_root(),
        root_with_canonical_pending,
        "same-key key_id drift must scrub the staged pending entry instead of silently rebinding it to a new slot"
    );
    assert_eq!(
        state.state_root(),
        StateStore::new().state_root(),
        "same-key key_id drift should return to the empty baseline root after fail-closed scrubbing"
    );
}

#[test]
fn restore_pending_gov_update_identical_reentry_does_not_skip_same_key_id_alias_scrub() {
    let mut state = StateStore::new();
    let snapshot = PendingGovParamUpdate {
        key_id: 7_201,
        key: "challenge_min_bond".into(),
        value: "6000".into(),
        activate_at_height: 1_020,
    };

    state.restore_pending_gov_update("challenge_min_bond", Some(snapshot.clone()));
    let root_with_canonical_pending = state.state_root();
    assert!(state.pending_gov_update("challenge_min_bond").is_some());

    state.pending_gov_updates.insert(
        "max_block_ms".into(),
        PendingGovParamUpdate {
            key_id: snapshot.key_id,
            key: "max_block_ms".into(),
            value: "400".into(),
            activate_at_height: 1_021,
        },
    );
    state.invalidate_state_root_cache();
    let root_with_alias = state.state_root();
    assert_ne!(
        root_with_alias, root_with_canonical_pending,
        "sanity: a same-key_id alias should perturb the root before identical reentry"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "sanity: canonical accessor should fail closed while a same-key_id alias is present"
    );

    state.restore_pending_gov_update("challenge_min_bond", Some(snapshot));

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "identical reentry must not bypass fail-closed handling once a same-key_id alias appears"
    );
    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "identical reentry should scrub the conflicting alias instead of leaving the poisoned slot behind"
    );
    assert_eq!(
        state.state_root(),
        StateStore::new().state_root(),
        "identical reentry should rewind to the empty baseline once same-key_id aliases force fail-closed scrubbing"
    );
}
