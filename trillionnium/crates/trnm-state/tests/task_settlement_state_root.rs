use trnm_state::*;
use trnm_types::*;

#[test]
fn task_settlement_snapshot_affects_state_root() {
    let mut without_settlement = StateStore::new();
    let mut with_settlement = StateStore::new();

    let metadata = TaskMetadata {
        note: Some("settled task".into()),
        task_type: Some("inference".into()),
        input_hash: Some("ab".repeat(32)),
        model: None,
        provenance: None,
        metering: None,
        settlement: None,
    };

    let base_task = TaskObject {
        task_id: 405,
        creator: "alice".into(),
        bounty: 25,
        status: TaskStatus::Completed,
        proof_type: ProofType::Fraud,
        metadata: Some(metadata.clone()),
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

    let mut settled_task = base_task.clone();
    settled_task.metadata = Some(TaskMetadata {
        settlement: Some(TaskSettlementSnapshot {
            settlement_schema: "poco_v1".into(),
            tokenizer_id: "llama3-tokenizer".into(),
            tokenizer_version: "1.0.0".into(),
            output_hash: format!("0x{}", "de".repeat(32)),
            output_token_count: 512,
            output_root: Some(format!("0x{}", "ad".repeat(32))),
            output_span_commitment: None,
        }),
        ..metadata
    });

    without_settlement.put_task_new(base_task).unwrap();
    with_settlement.put_task_new(settled_task).unwrap();

    assert_ne!(
        without_settlement.state_root(),
        with_settlement.state_root(),
        "state_root must include threaded settlement snapshots so PoCO settlement evidence cannot be silently omitted"
    );
}
