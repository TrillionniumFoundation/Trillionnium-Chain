use trnm_state::*;
use trnm_types::*;

#[test]
fn restore_task_rejects_terminal_collateral_retention_with_zero_challenge_deadline() {
    let mut state = StateStore::new();

    state.restore_task(
        40801,
        Some(TaskObject {
            task_id: 40801,
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
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(0),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(21),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(7),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 2,
        }),
    );

    assert!(
        state.get_task(40801).is_none(),
        "restore_task must fail closed when retained terminal collateral metadata zeroes the challenge deadline that bounds sponsor-funded proof retention"
    );
}
