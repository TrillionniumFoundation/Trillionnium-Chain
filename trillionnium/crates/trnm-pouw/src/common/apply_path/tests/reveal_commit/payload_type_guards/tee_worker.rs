use super::*;

#[test]
fn tee_reveal_rejects_noncanonical_worker_in_legacy_committed_state_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79, "alice".into(), 10).unwrap();

    // Forge a legacy Committed+TEE task with malformed worker identity.
    // This must fail closed before proof verification, even if proof bytes are present.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let malformed_worker = " worker1 ".to_string();
    let bad_task = TaskObject {
        task_id: 79,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some(malformed_worker.clone()),
        committed_hash: Some(compute_commitment(
            79,
            &result_hash,
            &reveal_salt,
            &malformed_worker,
        )),
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
    let r2 = st.update_task(r1, bad_task).unwrap();

    let proof = b"TEE:task_id=79,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account")));

    // Fail-closed behavior: state must remain Committed and unset result hash.
    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_newline_suffixed_worker_in_legacy_committed_state_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7900, "alice".into(), 10).unwrap();

    // Legacy/corrupted state may carry worker ids with hidden newline suffixes.
    // Reveal must fail closed before proof verification and before terminal mutation.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let malformed_worker = "worker1\n".to_string();
    let bad_task = TaskObject {
        task_id: 7900,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some(malformed_worker.clone()),
        committed_hash: Some(compute_commitment(
            7900,
            &result_hash,
            &reveal_salt,
            &malformed_worker,
        )),
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
    let r2 = st.update_task(r1, bad_task).unwrap();

    let proof = b"TEE:task_id=7900,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
