use super::*;

#[test]
fn emergency_pause_risk_gate_classification_is_stable() {
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed_hash = compute_commitment(1, &result_hash, &reveal_salt, "worker");

    let txs = [
        MockTx::CreateTask {
            task_id: 1,
            creator: "alice".into(),
            bounty: 100,
        },
        MockTx::AcceptTask {
            task_id: 1,
            worker: "worker".into(),
        },
        MockTx::Commit {
            task_id: 1,
            worker: "worker".into(),
            committed_hash,
        },
        MockTx::Reveal {
            task_id: 1,
            result_hash,
            reveal_salt,
        },
        MockTx::Challenge {
            task_id: 1,
            challenger: "challenger".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 1,
            slash_worker: true,
            resolver: "governance.resolve_authority".into(),
        },
    ];

    for tx in &txs {
        assert_eq!(
            is_high_risk_tx(tx),
            expected_high_risk_tx_exhaustive(tx),
            "pause risk gate drifted for tx variant: {:?}",
            tx
        );
    }
}
