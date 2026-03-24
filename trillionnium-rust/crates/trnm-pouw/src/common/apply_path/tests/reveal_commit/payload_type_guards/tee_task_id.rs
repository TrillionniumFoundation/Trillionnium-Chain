use super::*;

#[test]
fn tee_reveal_rejects_duplicate_task_id_binding_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 790, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(790, &result_hash, &reveal_salt, &worker);
    let committed_task = TaskObject {
        task_id: 790,
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
    let r2 = st.update_task(r1, committed_task).unwrap();

    // Duplicate task_id binding must fail closed (before any state transition).
    let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=790,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 792, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(792, &result_hash, &reveal_salt, &worker);
    let committed_task = TaskObject {
        task_id: 792,
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
    let r2 = st.update_task(r1, committed_task).unwrap();

    // Quoted trailing-space alias plus canonical task_id must still be treated
    // as duplicate binding and fail closed before any mutation.
    let proof = b"TEE:task_id=\"792 \",worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=792,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn tee_reveal_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 794, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(794, &result_hash, &reveal_salt, &worker);
    let committed_task = TaskObject {
        task_id: 794,
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
    let r2 = st.update_task(r1, committed_task).unwrap();

    // Quoted leading-space alias plus canonical task_id must still be treated
    // as duplicate binding and fail closed before any mutation.
    let proof = b"TEE:task_id=\" 794\",worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=794,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}
