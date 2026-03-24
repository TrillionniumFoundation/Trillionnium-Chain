use super::*;

#[test]
fn invalid_zk_proof_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7006, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Invalid ZK proof payload must be rejected fail-closed.
    let proof = b"BAD_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on verifier rejection.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_proof_type_mismatch_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7007, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7007, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Deliberately mismatched proof_type binding should be rejected fail-closed.
    let proof = b"ZK:task_id=7007,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on invalid envelope binding.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.challenge_deadline_height.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_proof_type_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7008, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7008, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Duplicate proof_type binding must fail closed.
    let proof = b"ZK:task_id=7008,worker=worker1,proof_type=zk,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7018, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7018, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted trailing-space alias plus canonical proof_type must still be
    // treated as a duplicate binding and fail closed.
    let proof = b"ZK:task_id=7018,worker=worker1,proof_type=\"zk \",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_proof_type_binding_with_single_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted trailing-space alias plus canonical proof_type must
    // still be treated as duplicate proof_type binding and fail closed.
    let proof = b"ZK:task_id=7027,worker=worker1,proof_type='zk ',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_proof_type_binding_with_single_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted leading-space alias plus canonical proof_type must
    // still be treated as duplicate proof_type binding and fail closed.
    let proof = b"ZK:task_id=7028,worker=worker1,proof_type=' zk',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_proof_type_binding_with_double_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7029, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7029, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Double-quoted leading-space alias plus canonical proof_type must
    // still be treated as duplicate proof_type binding and fail closed.
    let proof = b"ZK:task_id=7029,worker=worker1,proof_type=\" zk\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_proof_without_crypto_backend_rejects_reveal_and_preserves_committed_state() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7004, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [3u8; 32];
    let reveal_salt = [4u8; 32];
    let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=7004,worker=worker1,proof_type=zk,result_hash=0303030303030303030303030303030303030303030303030303030303030303,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
    );

    let final_task = st.get_task(r3.id).unwrap();
    assert_eq!(final_task.status, TaskStatus::Committed);
    assert!(final_task.result_hash.is_none());
    assert!(final_task.reveal_salt.is_none());
    assert!(final_task.challenge_deadline_height.is_none());
    assert!(final_task.resolve_deadline_height.is_none());
}
