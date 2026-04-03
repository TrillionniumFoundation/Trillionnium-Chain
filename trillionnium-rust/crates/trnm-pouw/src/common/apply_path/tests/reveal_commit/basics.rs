use super::*;

#[test]
fn forged_reveal_is_rejected() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 1, "alice".into(), 1).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let bad_reveal = apply_reveal_result(&mut st, r3, [3u8; 32], reveal_salt, None).unwrap_err();
    assert!(matches!(bad_reveal, PouwError::CommitmentMismatch));
}

#[test]
fn commit_rejects_noncanonical_worker_binding_in_assigned_state() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7_801, "alice".into(), 10).unwrap();

    let bad_task = TaskObject {
        task_id: 7_801,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Assigned,
        proof_type: Default::default(),
        metadata: None,
        worker: Some(" worker1 ".into()),
        committed_hash: None,
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

    let before = st.get_task(r2.id).unwrap();
    let err = apply_commit_result(&mut st, r2, " worker1 ".into(), [9u8; 32]).unwrap_err();
    assert!(matches!(err, PouwError::State(reason) if reason == "non-canonical worker account"));

    let task_after = st.get_task(before.task_id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Assigned);
    assert!(task_after.committed_hash.is_none());
    assert!(task_after.reveal_deadline_height.is_none());
}

#[test]
fn reveal_missing_worker_is_mapped() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 77, "alice".into(), 10).unwrap();

    // Forge an Assigned+Committed task with worker=None to exercise defensive mapping.
    let bad_task = TaskObject {
        task_id: 77,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
        committed_hash: Some([1u8; 32]),
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

    let err = apply_reveal_result(&mut st, r2.clone(), [2u8; 32], [3u8; 32], None).unwrap_err();
    assert!(matches!(err, PouwError::MissingWorker));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_missing_worker_fails_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 779, "alice".into(), 10).unwrap();

    // Legacy/corrupted state may lose assigned worker identity after commit.
    // TEE proof verification must fail closed before any terminal mutation.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(779, &result_hash, &reveal_salt, "worker1");
    let bad_task = TaskObject {
        task_id: 779,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: None,
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

    let proof = b"TEE:task_id=779,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::MissingWorker));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn zk_reveal_missing_worker_fails_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 780, "alice".into(), 10).unwrap();

    // Legacy/corrupted state may lose assigned worker identity after commit.
    // ZK proof verification must fail closed before any terminal mutation.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(780, &result_hash, &reveal_salt, "worker1");
    let bad_task = TaskObject {
        task_id: 780,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Zk,
        metadata: None,
        worker: None,
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

    let proof = b"ZK:task_id=780,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::MissingWorker));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_noncanonical_worker_binding_before_verification() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 781, "alice".into(), 10).unwrap();

    // Legacy/corrupted state may carry non-canonical worker account ids.
    // TEE proof verification must fail closed before any terminal mutation.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(781, &result_hash, &reveal_salt, " worker1 ");
    let bad_task = TaskObject {
        task_id: 781,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Tee,
        metadata: None,
        worker: Some(" worker1 ".into()),
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

    let proof = b"TEE:task_id=781,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(reason) if reason == "non-canonical worker account"));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
