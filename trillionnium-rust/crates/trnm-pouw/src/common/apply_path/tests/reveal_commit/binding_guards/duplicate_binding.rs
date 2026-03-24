use super::*;

#[test]
fn tee_reveal_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78922, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(78922, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "TEE:task_id=78922,worker=worker1，worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
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
fn zk_reveal_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79123, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79123, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = "ZK:task_id=79123,worker=worker1，worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
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
fn tee_reveal_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7903, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7903, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=7903;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;task_id=7903;quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_semicolon_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79032, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79032, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=79032;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;worker=worker1;quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_semicolon_delimited_duplicate_result_hash_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 790322, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(790322, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=790322;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;result_hash=0202020202020202020202020202020202020202020202020202020202020202;quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79033, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79033, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=79033;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;proof_type=tee;quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_comma_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation()
{
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79031, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79031, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=79031,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=79031,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_comma_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation()
{
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79033, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79033, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=79033,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=79033,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7904, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7904, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=7904;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;task_id=7904;seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_semicolon_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79041, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79041, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=79041;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;worker=worker1;seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79042, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79042, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=79042;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;proof_type=zk;seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_semicolon_delimited_duplicate_result_hash_binding_fail_closed_without_state_mutation(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79043, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79043, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:task_id=79043;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;result_hash=0202020202020202020202020202020202020202020202020202020202020202;seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
