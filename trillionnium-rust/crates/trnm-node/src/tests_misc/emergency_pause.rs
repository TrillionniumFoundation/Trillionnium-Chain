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

#[test]
fn emergency_pause_rejects_all_resolve_variants_independent_of_resolver_identity() {
    let resolve_txs = [
        MockTx::Resolve {
            task_id: 7,
            slash_worker: true,
            resolver: "governance.resolve_authority".into(),
        },
        MockTx::Resolve {
            task_id: 7,
            slash_worker: false,
            resolver: "authority-a".into(),
        },
    ];

    for tx in &resolve_txs {
        assert!(
            is_high_risk_tx(tx),
            "resolve risk classification must not drift based on resolver identity or slash mode: {:?}",
            tx
        );
        assert!(
            is_rejected_by_emergency_pause(true, tx),
            "paused node must reject every resolve variant: {:?}",
            tx
        );
        assert!(
            !is_rejected_by_emergency_pause(false, tx),
            "unpaused node must not reject resolve purely due to classification helper: {:?}",
            tx
        );
    }
}
