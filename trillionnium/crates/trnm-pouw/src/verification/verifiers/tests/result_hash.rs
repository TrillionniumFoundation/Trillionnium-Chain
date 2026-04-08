use super::*;

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,result_hash=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_malformed_secondary_result_hash_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,result_hash=,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,Result_Hash=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_with_quoted_alias_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,\"result_hash\"=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_with_double_quoted_alias_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,\"result_hash\"=\"abababababababababababababababababababababababababababababababab\",proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,\" result_hash\"=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,\"result_hash \"=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_with_unclosed_quoted_alias_fail_closed(
) {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,\"result_hash\"=\"abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_prioritizes_duplicate_result_hash_over_mismatch_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,result_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,result_hash=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_result_hash_identifier_spoof_fail_closed() {
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 1,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
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
            b"ZK:task_id=42,worker=worker1,proof_type=zk,xresult_hash=abababababababababababababababababababababababababababababababab,proof=ok",
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_duplicate_result_hash_binding_without_hash_context_fail_closed() {
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
fn verify_bound_envelope_rejects_unexpected_result_hash_binding_without_hash_context_fail_closed() {
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

