use super::*;

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
fn verify_bound_envelope_rejects_signed_task_id_binding_fail_closed() {
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
            b"TEE:task_id=+42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_signed_task_id_binding_fail_closed() {
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
            b"TEE:task_id=\"+42\",worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_negative_signed_task_id_binding_fail_closed() {
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
            b"TEE:task_id=\"-42\",worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_negative_signed_task_id_binding_fail_closed() {
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
            b"TEE:task_id=-42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_plus_signed_task_id_binding_fail_closed() {
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
            "TEE:task_id=＋42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok"
                .as_bytes(),
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_fullwidth_plus_signed_task_id_binding_fail_closed() {
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
            "TEE:task_id=\"＋42\",worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok"
                .as_bytes(),
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_task_id_with_leading_space_fail_closed() {
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
            b"TEE:task_id=\" 42\",worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_quoted_task_id_with_trailing_space_fail_closed() {
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
            b"TEE:task_id=\"42 \",worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate task_id binding")
    ));
}
