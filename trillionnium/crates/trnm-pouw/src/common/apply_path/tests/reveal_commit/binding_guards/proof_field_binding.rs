use super::*;

#[test]
fn tee_reveal_rejects_result_hash_binding_with_repeated_hex_prefix_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7892, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7892, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=7892,worker=worker1,proof_type=tee,result_hash=0x0x0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_fullwidth_equals_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78921, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(78921, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "TEE:task_id=78921,worker=worker1,proof_type=tee,result_hash＝0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_fullwidth_colon_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78923, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(78923, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "TEE:task_id=78923,worker=worker1,proof_type=tee,result_hash：0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_fullwidth_colon_proof_type_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78924, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(78924, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "TEE:task_id=78924,worker=worker1,proof_type：tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_missing_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 790, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(790, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=790,worker=worker1,proof_type=tee,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_missing_proof_type_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7901, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7901, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=7901,worker=worker1,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_worker_binding_mismatch_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7902, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7902, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=7902,worker=worker2,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_missing_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 791, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(791, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=791,worker=worker1,proof_type=zk,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_missing_proof_type_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7911, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7911, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=7911,worker=worker1,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_worker_binding_mismatch_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7912, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7912, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=7912,worker=worker2,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_fullwidth_equals_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79121, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79121, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "ZK:task_id=79121,worker=worker1,proof_type=zk,result_hash＝0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_fullwidth_colon_result_hash_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79122, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79122, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "ZK:task_id=79122,worker=worker1,proof_type=zk,result_hash：0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_fullwidth_colon_proof_type_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79124, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79124, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "ZK:task_id=79124,worker=worker1,proof_type：zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_result_hash_binding_with_repeated_hex_prefix_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79122, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79122, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=79122,worker=worker1,proof_type=zk,result_hash=0x0x0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
