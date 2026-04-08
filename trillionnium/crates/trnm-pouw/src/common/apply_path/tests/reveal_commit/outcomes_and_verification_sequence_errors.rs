use super::*;

#[test]
fn tee_reveal_rejects_legacy_task_id_binding_mismatch_fail_closed() {
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

    let mut corrupted = st.get_task(r3.id).unwrap();
    corrupted.task_id = r3.id + 1;
    st.update_task(r3.clone(), corrupted).unwrap();

    let proof = b"TEE:task_id=7003,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_signed_task_id_binding_fail_closed_without_state_mutation() {
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

    // Signed numeric task_id is non-canonical and must fail closed.
    let proof = b"TEE:task_id=+7011,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_negative_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 70115, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(70115, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Negative signed task_id is non-canonical and must fail closed.
    let proof = b"TEE:task_id=-70115,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_quoted_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 70115, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(70115, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted signed numeric task_id is non-canonical and must fail closed.
    let proof = b"TEE:task_id='+70115',worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_fullwidth_plus_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7013, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7013, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Fullwidth signed numeric task_id is non-canonical and must fail closed.
    let proof = "TEE:task_id=＋7013,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_legacy_task_id_binding_mismatch_fail_closed() {
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

    let mut corrupted = st.get_task(r3.id).unwrap();
    corrupted.task_id = r3.id + 1;
    st.update_task(r3.clone(), corrupted).unwrap();

    let proof = b"ZK:task_id=7007,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7012, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7012, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Signed numeric task_id is non-canonical and must fail closed.
    let proof = b"ZK:task_id=+7012,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_negative_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 70125, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(70125, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Negative signed numeric task_id is non-canonical and must fail closed.
    let proof = b"ZK:task_id=-70125,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_quoted_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 70126, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(70126, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Quoted signed numeric task_id is non-canonical and must fail closed.
    let proof = b"ZK:task_id='+70126',worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_fullwidth_plus_signed_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7014, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7014, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Fullwidth signed numeric task_id is non-canonical and must fail closed.
    let proof = "ZK:task_id=＋7014,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_duplicate_task_id_binding_with_single_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Single-quoted trailing-space alias plus canonical task_id must
    // still be treated as duplicate task_id binding and fail closed.
    let proof = b"ZK:task_id='7026 ',task_id=7026,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7016, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7016, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Case-variant duplicate task_id binding must fail closed.
    let proof = b"ZK:task_id=7016,TASK_ID=7016,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Ensure task does not advance on malformed envelope bindings.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}
