use super::*;

#[test]
fn zk_proof_accepts_uppercase_hex_prefix_in_result_hash_binding() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 8701, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [0xcdu8; 32];
    let reveal_salt = [4u8; 32];
    let committed = compute_commitment(8701, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Accept canonical envelope tuple when result_hash uses uppercase 0X hex prefix.
    let proof = b"ZK:task_id=8701,worker=worker1,proof_type=zk,result_hash=0XCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD,seal=SEAL_XYZ".to_vec();
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
}

#[test]
fn zk_proof_accepts_uppercase_proof_type_binding() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 8702, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [0xceu8; 32];
    let reveal_salt = [6u8; 32];
    let committed = compute_commitment(8702, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Accept canonical envelope tuple when proof_type value uses uppercase alias.
    let proof = b"ZK:task_id=8702,worker=worker1,proof_type=ZK,result_hash=CECECECECECECECECECECECECECECECECECECECECECECECECECECECECECECECE,seal=SEAL_XYZ".to_vec();
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
}
