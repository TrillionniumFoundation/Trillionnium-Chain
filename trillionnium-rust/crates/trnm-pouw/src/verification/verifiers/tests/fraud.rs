use super::*;

#[test]
fn verify_bound_envelope_rejects_unexpected_worker_binding_without_worker_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"FRAUD:task_id=42,proof_type=fraud,worker=w1,proof=ok",
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_colon_unexpected_worker_binding_without_worker_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            "FRAUD:task_id=42,proof_type=fraud,worker：w1,proof=ok".as_bytes(),
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_worker_binding_without_worker_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            "FRAUD:task_id=42,proof_type=fraud,worker＝w1,proof=ok".as_bytes(),
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_colon_unexpected_result_hash_binding_without_hash_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            "FRAUD:task_id=42,proof_type=fraud,result_hash：aa,proof=ok".as_bytes(),
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_result_hash_binding_without_hash_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            "FRAUD:task_id=42,proof_type=fraud,result_hash＝aa,proof=ok".as_bytes(),
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_quoted_result_hash_binding_without_hash_context_for_fraud_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
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

    assert!(matches!(
        verify_bound_envelope(
            &task,
            "FRAUD:task_id=42,proof_type=fraud,\"result_hash\"＝aa,proof=ok".as_bytes(),
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

