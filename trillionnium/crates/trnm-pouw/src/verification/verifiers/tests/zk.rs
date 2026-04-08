use super::*;

#[test]
fn verify_bound_envelope_rejects_duplicate_worker_binding_without_worker_context_for_zk_fail_closed(
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
            b"ZK:task_id=42,proof_type=zk,worker=w1,Worker=w2,proof=ok",
            b"ZK:",
            "ZK proof"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

#[test]
fn verify_bound_envelope_rejects_fullwidth_equals_then_ascii_worker_binding_for_zk_fail_closed()
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
            "ZK:task_id=42,worker＝worker1,worker=worker1,proof_type=zk,result_hash=abababababababababababababababababababababababababababababababab,proof=ok"
                .as_bytes(),
            b"ZK:",
            "ZK receipt"
        ),
        VerificationResult::Invalid(msg) if msg.contains("duplicate worker binding")
    ));
}

