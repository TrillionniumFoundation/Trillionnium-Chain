use super::*;

#[test]
fn verify_bound_envelope_rejects_prefix_without_visible_body_fail_closed() {
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
        verify_bound_envelope(&task, b"\xef\xbb\xbfTEE:\n\t", b"TEE:", "TEE receipt"),
        VerificationResult::Invalid(msg) if msg.contains("Invalid TEE receipt envelope")
    ));
}

#[test]
fn verify_bound_envelope_rejects_mongolian_vowel_separator_only_payload_fail_closed() {
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
        verify_bound_envelope(&task, "TEE:\u{180e}".as_bytes(), b"TEE:", "TEE receipt"),
        VerificationResult::Invalid(msg) if msg.contains("Invalid TEE receipt envelope")
    ));
}

#[test]
fn verify_bound_envelope_rejects_mongolian_vowel_separator_only_payload_for_zk_fail_closed() {
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
        verify_bound_envelope(&task, "ZK:\u{180e}".as_bytes(), b"ZK:", "ZK receipt"),
        VerificationResult::Invalid(msg) if msg.contains("Invalid ZK receipt envelope")
    ));
}

#[test]
fn verify_bound_envelope_rejects_invisible_separator_only_payload_fail_closed() {
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
        verify_bound_envelope(&task, "TEE:\u{2063}".as_bytes(), b"TEE:", "TEE receipt"),
        VerificationResult::Invalid(msg) if msg.contains("Invalid TEE receipt envelope")
    ));
}

