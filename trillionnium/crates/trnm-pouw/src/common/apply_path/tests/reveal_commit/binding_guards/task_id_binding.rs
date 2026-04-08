use super::*;

#[test]
fn tee_reveal_rejects_malformed_secondary_task_id_binding_fail_closed_before_verification() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7882, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7882, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Fail closed when the proof envelope repeats task_id with a malformed
    // secondary value, even if the first binding appears canonical.
    let proof = b"TEE:task_id=7882,task_id=7882x,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_task_id_identifier_spoof_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7900, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7900, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:x_task_id=7900,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_task_id_identifier_spoof_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79001, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79001, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"ZK:x_task_id=79001,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_proof_type_identifier_spoof_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 79002, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(79002, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let proof = b"TEE:task_id=79002,worker=worker1,x_proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 781, "alice".into(), 10).unwrap();

    // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(780, &result_hash, &reveal_salt, &worker);
    let bad_task = TaskObject {
        task_id: 780,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some(worker),
        committed_hash: Some(committed),
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

    let proof = b"TEE:task_id=780,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn zk_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 782, "alice".into(), 10).unwrap();

    // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(781, &result_hash, &reveal_salt, &worker);
    let bad_task = TaskObject {
        task_id: 781,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
        metadata: None,
        worker: Some(worker),
        committed_hash: Some(committed),
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

    let proof = b"ZK:task_id=781,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn fraud_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 783, "alice".into(), 10).unwrap();

    // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(782, &result_hash, &reveal_salt, &worker);
    let bad_task = TaskObject {
        task_id: 782,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker),
        committed_hash: Some(committed),
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

    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, None).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}
