use super::*;

#[test]
fn verify_bound_envelope_rejects_task_id_identifier_spoof_fail_closed() {
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
            b"TEE:xtask_id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_underscore_task_id_identifier_spoof_fail_closed() {
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
            "TEE:task＿id=42,worker=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok"
                .as_bytes(),
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing task_id binding")
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
fn verify_bound_envelope_rejects_fullwidth_underscore_result_hash_identifier_spoof_fail_closed()
{
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
            "ZK:task_id=42,worker=worker1,proof_type=zk,result＿hash=abababababababababababababababababababababababababababababababab,proof=ok"
                .as_bytes(),
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing result_hash binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_proof_type_identifier_spoof_fail_closed() {
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
            b"TEE:task_id=42,worker=worker1,xproof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok",
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_underscore_proof_type_identifier_spoof_fail_closed()
{
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
            "TEE:task_id=42,worker=worker1,proof＿type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok"
                .as_bytes(),
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing proof_type binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_underscore_worker_identifier_spoof_fail_closed() {
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
            "TEE:task_id=42,worke＿r=worker1,proof_type=tee,result_hash=abababababababababababababababababababababababababababababababab,quote=ok"
                .as_bytes(),
            b"TEE:",
            "TEE receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("missing worker binding")
    ));
}
