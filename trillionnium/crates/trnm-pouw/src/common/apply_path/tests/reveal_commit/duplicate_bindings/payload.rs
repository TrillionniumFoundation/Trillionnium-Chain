use super::*;

#[test]
fn invalid_tee_proof_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7002, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7002, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Invalid proof (doesn't start with TE)
    let proof = b"BAD_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Fail closed on verifier rejection: committed task must remain unchanged.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.challenge_deadline_height.is_none());
}

#[test]
fn invalid_utf8_tee_proof_rejects_reveal_fail_closed_without_missing_payload_mapping() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7003, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7003, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Invalid UTF-8 payload should still be treated as present proof data and
    // fail through verifier path (not remapped to missing payload).
    let proof = vec![0xff, 0xfe, 0xfd];
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed") && !msg.contains("missing proof payload"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.challenge_deadline_height.is_none());
}

#[test]
fn invalid_utf8_zk_proof_rejects_reveal_fail_closed_without_missing_payload_mapping() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7004, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Invalid UTF-8 payload should still be treated as present proof data and
    // fail through verifier path (not remapped to missing payload).
    let proof = vec![0xff, 0xfe, 0xfd];
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed") && !msg.contains("missing proof payload"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.challenge_deadline_height.is_none());
}
