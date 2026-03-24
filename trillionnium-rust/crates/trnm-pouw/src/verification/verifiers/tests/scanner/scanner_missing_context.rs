use super::*;

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_without_worker_context_fail_closed() {
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
            b"FRAUD:task_id=42,proof_type=fraud,worker=w1,worker=w2,proof=ok",
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_without_hash_context_fail_closed(
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
            b"FRAUD:task_id=42,proof_type=fraud,result_hash=aa,result_hash=bb,proof=ok",
            b"FRAUD:",
            "Fraud proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_unexpected_worker_binding_without_worker_context_fail_closed()
{
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
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
            b"TEE:task_id=42,proof_type=tee,worker=w1,proof=ok",
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_malformed_unexpected_worker_binding_without_worker_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
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
            b"TEE:task_id=42,proof_type=tee,worker=,proof=ok",
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_unexpected_result_hash_binding_without_hash_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,proof_type=zk,result_hash=aa,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_malformed_unexpected_result_hash_binding_without_hash_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,proof_type=zk,result_hash=,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_worker_binding_without_worker_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
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
            "TEE:task_id=42,proof_type=tee,worker＝w1,quote=ok".as_bytes(),
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_quoted_worker_binding_without_worker_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
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
            "TEE:task_id=42,proof_type=tee,\"worker\"＝w1,quote=ok".as_bytes(),
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_colon_unexpected_worker_binding_without_worker_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
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
            "TEE:task_id=42,proof_type=tee,worker：w1,quote=ok".as_bytes(),
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_colon_unexpected_result_hash_binding_without_hash_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            "ZK:task_id=42,proof_type=zk,result_hash：aa,proof=ok".as_bytes(),
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_unexpected_quoted_result_hash_binding_without_hash_context_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            "ZK:task_id=42,proof_type=zk,\"result_hash\"＝aa,proof=ok".as_bytes(),
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("unexpected result_hash binding")
    ));
}
