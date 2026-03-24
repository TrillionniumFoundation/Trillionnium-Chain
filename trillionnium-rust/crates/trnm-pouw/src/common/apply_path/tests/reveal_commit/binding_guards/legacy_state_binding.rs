use super::*;

#[test]
fn tee_reveal_rejects_matching_legacy_committed_result_hash_binding_fail_closed_before_verification(
) {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 788, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(788, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Simulate legacy state where committed result_hash was persisted early but
    // still matches the reveal payload. Verifiable tasks must fail closed before
    // verification when committed state is prebound.
    let mut prebound = st.get_task(r3.id).unwrap();
    prebound.result_hash = Some(result_hash);
    let r3 = st.update_task(r3, prebound).unwrap();

    let proof = b"TEE:task_id=788,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash prebound"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert_eq!(task_after.result_hash, Some(result_hash));
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_matching_legacy_committed_result_hash_binding_fail_closed_before_verification()
{
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7881, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7881, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Simulate legacy state where committed result_hash was persisted early but
    // still matches the reveal payload. Verifiable tasks must fail closed before
    // verification when committed state is prebound.
    let mut prebound = st.get_task(r3.id).unwrap();
    prebound.result_hash = Some(result_hash);
    let r3 = st.update_task(r3, prebound).unwrap();

    let proof = b"ZK:task_id=7881,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash prebound"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert_eq!(task_after.result_hash, Some(result_hash));
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 789, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(789, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Simulate legacy/corrupted state where object reference id is still 789
    // but the persisted task body drifts to a different task_id.
    let mut drifted = st.get_task(r3.id).unwrap();
    drifted.task_id = 1789;
    let r3 = st.update_task(r3, drifted).unwrap();

    let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7891, "alice".into(), 10).unwrap();
    let mut zk_task = st.get_task(r1.id).unwrap();
    zk_task.proof_type = ProofType::Zk;
    let r1 = st.update_task(r1, zk_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7891, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Simulate legacy/corrupted state where object reference id is still 7891
    // but the persisted task body drifts to a different task_id.
    let mut drifted = st.get_task(r3.id).unwrap();
    drifted.task_id = 17891;
    let r3 = st.update_task(r3, drifted).unwrap();

    let proof = b"ZK:task_id=7891,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn fraud_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7893, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7893, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Simulate legacy/corrupted state where object reference id is still 7893
    // but the persisted task body drifts to a different task_id.
    let mut drifted = st.get_task(r3.id).unwrap();
    drifted.task_id = 17893;
    let r3 = st.update_task(r3, drifted).unwrap();

    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_legacy_committed_result_hash_drift_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 783, "alice".into(), 10).unwrap();

    // Simulate legacy drift where Committed state already carries a stale result_hash.
    // Reveal verification must rebind to the reveal arguments and proof envelope bindings.
    let result_hash = [2u8; 32];
    let stale_result_hash = [9u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(783, &result_hash, &reveal_salt, &worker);
    let legacy_task = TaskObject {
        task_id: 783,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some(worker),
        committed_hash: Some(committed),
        // Legacy/corrupted optional field drift.
        result_hash: Some(stale_result_hash),
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
    let r2 = st.update_task(r1, legacy_task).unwrap();

    let proof = b"TEE:task_id=783,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash drift"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert_eq!(task_after.result_hash, Some(stale_result_hash));
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_rejects_legacy_committed_result_hash_drift_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 784, "alice".into(), 10).unwrap();

    // Simulate legacy drift where Committed state already carries a stale result_hash.
    // Reveal verification must rebind to the reveal arguments and proof envelope bindings.
    let result_hash = [2u8; 32];
    let stale_result_hash = [9u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(784, &result_hash, &reveal_salt, &worker);
    let legacy_task = TaskObject {
        task_id: 784,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
        metadata: None,
        worker: Some(worker),
        committed_hash: Some(committed),
        // Legacy/corrupted optional field drift.
        result_hash: Some(stale_result_hash),
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
    let r2 = st.update_task(r1, legacy_task).unwrap();

    let proof = b"ZK:task_id=784,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash drift"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert_eq!(task_after.result_hash, Some(stale_result_hash));
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_noncanonical_worker_in_legacy_committed_state() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78, "alice".into(), 10).unwrap();

    // Forge a legacy Committed task with malformed worker identity.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let malformed_worker = " worker1 ".to_string();
    let bad_task = TaskObject {
        task_id: 78,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some(malformed_worker.clone()),
        committed_hash: Some(compute_commitment(
            78,
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

    let err = apply_reveal_result(&mut st, r2, result_hash, reveal_salt, None).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account")));
}
