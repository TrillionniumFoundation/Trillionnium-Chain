use super::*;

#[test]
fn missing_tee_proof_rejects_reveal_fail_closed() {
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

    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Fail closed on missing payload: task must remain in Committed state.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn empty_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7007, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [3u8; 32];
    let reveal_salt = [4u8; 32];
    let committed = compute_commitment(7007, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some(Vec::new()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    // Fail closed on empty payload: task must remain Committed with no result hash.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn whitespace_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7024, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(7024, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some(b" \t\n\r ".to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn unicode_whitespace_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7025, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(7025, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{3000}\u{2003}\n".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn word_joiner_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{2060}".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn utf8_bom_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{feff}".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn missing_zk_proof_rejects_reveal_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7006, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

    // Fail closed on missing payload: task must remain in Committed state.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn empty_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7008, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [5u8; 32];
    let reveal_salt = [6u8; 32];
    let committed = compute_commitment(7008, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some(Vec::new()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    // Fail closed on empty payload: task must remain Committed with no result hash.
    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn unicode_whitespace_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [9u8; 32];
    let reveal_salt = [1u8; 32];
    let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{3000}\u{2003}\n".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn word_joiner_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [9u8; 32];
    let reveal_salt = [1u8; 32];
    let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{2060}".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn utf8_bom_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7029, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [9u8; 32];
    let reveal_salt = [1u8; 32];
    let committed = compute_commitment(7029, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{feff}".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]
fn utf8_bom_and_whitespace_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation()
{
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Zk;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [9u8; 32];
    let reveal_salt = [1u8; 32];
    let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let err = apply_reveal_result(
        &mut st,
        r3.clone(),
        result_hash,
        reveal_salt,
        Some("\u{feff}\u{3000}\n".as_bytes().to_vec()),
    )
    .unwrap_err();

    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}
