use super::*;

#[test]
fn reveal_rejects_blank_proof_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7891, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 7891,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            7891,
            &result_hash,
            &reveal_salt,
            &worker,
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
    let r2 = st.update_task(r1, drifted_task).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r2.clone(),
        result_hash,
        reveal_salt,
        Some(b" \t\n".to_vec()),
    )
    .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_utf8_bom_only_proof_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7892, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 7892,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            7892,
            &result_hash,
            &reveal_salt,
            &worker,
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
    let r2 = st.update_task(r1, drifted_task).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r2.clone(),
        result_hash,
        reveal_salt,
        Some(vec![0xEF, 0xBB, 0xBF]),
    )
    .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_unicode_whitespace_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7893, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 7893,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            7893,
            &result_hash,
            &reveal_salt,
            &worker,
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
    let r2 = st.update_task(r1, drifted_task).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r2.clone(),
        result_hash,
        reveal_salt,
        Some("\u{3000}\u{2003}".as_bytes().to_vec()),
    )
    .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_non_utf8_proof_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78931, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 78931,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            78931,
            &result_hash,
            &reveal_salt,
            &worker,
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
    let r2 = st.update_task(r1, drifted_task).unwrap();

    // Non-UTF8 payloads must also fail-closed for non-verifiable proof types.
    let err = apply_reveal_result(
        &mut st,
        r2.clone(),
        result_hash,
        reveal_salt,
        Some(vec![0xFF, 0xFE, 0x00, 0x80]),
    )
    .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn tee_reveal_rejects_utf8_bom_and_whitespace_only_payload_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7894, "alice".into(), 10).unwrap();
    let mut tee_task = st.get_task(r1.id).unwrap();
    tee_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, tee_task).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7894, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some(vec![0xEF, 0xBB, 0xBF, b' ', b'\t', b'\n']),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
