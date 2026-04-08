use super::*;

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_case_variant_duplicate_worker_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,Worker=worker1,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_quoted_alias_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=worker1,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,'worker'='worker1',quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=\"worker1\",quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=\" worker2\",quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=\"worker2 \",quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_with_unclosed_quoted_alias_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,\"worker\"=\"worker2,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_malformed_secondary_worker_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=\"\",quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_prioritizes_duplicate_worker_over_mismatch_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=attacker,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,worker=worker1,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_worker_with_trailing_space_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=\"worker1 \",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_worker_with_leading_space_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some("worker1".into()),
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
        version: 1,
    };

    assert!(matches!(
        verify_bound_envelope(
            &task,
            b"TEE:task_id=42,worker=\" worker1\",proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

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
fn verify_bound_envelope_rejects_unexpected_worker_binding_without_worker_context_fail_closed() {
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
fn verify_bound_envelope_rejects_duplicate_worker_binding_without_worker_context_for_tee_fail_closed(
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
            b"TEE:task_id=42,proof_type=tee,worker=w1,Worker=w2,proof=ok",
            b"TEE:",
            "TEE proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

