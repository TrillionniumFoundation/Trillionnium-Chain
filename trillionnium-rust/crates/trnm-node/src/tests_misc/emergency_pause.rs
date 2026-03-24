use super::*;

#[test]
fn emergency_pause_gates_only_high_risk_tx_when_paused() {
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
            is_rejected_by_emergency_pause(true, tx),
            expected_high_risk_tx_exhaustive(tx),
            "pause gate drifted for tx variant while paused: {:?}",
            tx
        );
        assert!(
            !is_rejected_by_emergency_pause(false, tx),
            "pause gate unexpectedly active while unpaused for tx variant: {:?}",
            tx
        );
    }
}

#[test]
fn emergency_pause_rejection_formula_is_exact_boolean_gate() {
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed_hash = compute_commitment(42, &result_hash, &reveal_salt, "worker");

    let txs = [
        MockTx::CreateTask {
            task_id: 42,
            creator: "alice".into(),
            bounty: 100,
        },
        MockTx::AcceptTask {
            task_id: 42,
            worker: "worker".into(),
        },
        MockTx::Commit {
            task_id: 42,
            worker: "worker".into(),
            committed_hash,
        },
        MockTx::Reveal {
            task_id: 42,
            result_hash,
            reveal_salt,
        },
        MockTx::Challenge {
            task_id: 42,
            challenger: "challenger".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 42,
            slash_worker: false,
            resolver: "governance.resolve_authority".into(),
        },
    ];

    for tx in &txs {
        for paused in [false, true] {
            assert_eq!(
                is_rejected_by_emergency_pause(paused, tx),
                paused && is_high_risk_tx(tx),
                "emergency pause formula drifted: paused={} tx={:?}",
                paused,
                tx
            );
        }
    }
}
