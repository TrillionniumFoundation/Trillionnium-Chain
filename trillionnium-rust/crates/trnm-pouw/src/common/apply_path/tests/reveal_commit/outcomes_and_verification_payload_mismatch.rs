use super::*;

#[test]
fn tee_reveal_rejects_case_variant_duplicate_worker_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7014, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7014, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Case-variant duplicate worker binding must fail closed.
    let proof = b"TEE:task_id=7014,worker=worker1,Worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7015, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7015, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted trailing-space alias plus canonical worker binding must be
    // treated as duplicate worker binding and fail closed.
    let proof = b"TEE:task_id=7015,worker=\"worker1 \",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted leading-space alias plus canonical worker binding must still
    // be treated as duplicate worker binding and fail closed.
    let proof = b"TEE:task_id=7028,worker=\" worker1\",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7037, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7037, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Double-quoted alias plus canonical worker binding must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"TEE:task_id=7037,worker=\"worker1\",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7041, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7041, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted alias plus canonical worker binding must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"TEE:task_id=7041,worker='worker1',worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_result_hash_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7011, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7011, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Duplicate result_hash binding must fail closed.
    let proof = b"TEE:task_id=7011,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7017, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7017, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted trailing-space alias plus canonical result_hash must still be
    // treated as a duplicate binding and fail closed.
    let proof = b"TEE:task_id=7017,worker=worker1,proof_type=tee,result_hash=\"0101010101010101010101010101010101010101010101010101010101010101 \",result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7018, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7018, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted leading-space alias plus canonical result_hash must still be
    // treated as a duplicate binding and fail closed.
    let proof = b"TEE:task_id=7018,worker=worker1,proof_type=tee,result_hash=\" 0101010101010101010101010101010101010101010101010101010101010101\",result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7012, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7012, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Case-variant duplicate result_hash binding must fail closed.
    let proof = b"TEE:task_id=7012,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,Result_Hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_worker_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7013, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7013, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Duplicate worker binding must fail closed.
    let proof = b"ZK:task_id=7013,worker=worker1,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_case_variant_duplicate_worker_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7017, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7017, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Case-variant duplicate worker binding must fail closed.
    let proof = b"ZK:task_id=7017,worker=worker1,Worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7019, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7019, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted trailing-space alias plus canonical worker must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"ZK:task_id=7019,worker=worker1,\"worker\"=\"worker1 \",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7020, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7020, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted leading-space alias plus canonical worker must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"ZK:task_id=7020,worker=worker1,\"worker\"=\" worker1\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7021, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7021, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Double-quoted alias plus canonical worker binding must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"ZK:task_id=7021,worker=worker1,\"worker\"=\"worker1\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7025, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7025, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted alias plus canonical worker binding must still be
    // treated as duplicate worker binding and fail closed.
    let proof = b"ZK:task_id=7025,worker=worker1,'worker'='worker1',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7010, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7010, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Case-variant duplicate result_hash binding must fail closed.
    let proof = b"ZK:task_id=7010,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,Result_Hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
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

    // Quoted trailing-space alias plus canonical result_hash must still be
    // treated as duplicate result_hash binding and fail closed.
    let proof = b"ZK:task_id=7018,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,\"result_hash\"=\"0101010101010101010101010101010101010101010101010101010101010101 \",receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_result_hash_binding_with_single_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7020, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7020, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted leading-space alias plus canonical result_hash must
    // still be treated as duplicate result_hash binding and fail closed.
    let proof = b"ZK:task_id=7020,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,'result_hash'=' 0101010101010101010101010101010101010101010101010101010101010101',receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}
