use super::*;

#[test]
fn reveal_rejects_unexpected_proof_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 789, "alice".into(), 10).unwrap();

    // Legacy/corrupted proof_type drift may mark a proof-requiring task as Fraud.
    // If a payload is present, reject fail-closed instead of silently bypassing
    // envelope verification.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 789,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(789, &result_hash, &reveal_salt, &worker)),
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

    let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(
        err,
        PouwError::State(msg)
            if msg.contains("unexpected proof payload for non-verifiable proof type")
                && msg.contains("Fraud")
    ));

    // Fail-closed behavior: state must remain Committed and unset reveal artifacts.
    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_zk_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7890, "alice".into(), 10).unwrap();

    // Legacy/corrupted proof_type drift may mark a proof-requiring task as Fraud.
    // If a payload is present, reject fail-closed instead of silently bypassing
    // envelope verification, regardless of whether payload prefix is TEE or ZK.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 7890,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            7890,
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

    let proof = b"ZK:task_id=7890,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
    );

    // Fail-closed behavior: state must remain Committed and unset reveal artifacts.
    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_tee_payload_for_non_verifiable_proof_type_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 78901, "alice".into(), 10).unwrap();

    // Legacy/corrupted proof_type drift may carry a TEE envelope while task
    // state says Fraud. This must fail closed before any reveal mutation.
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let drifted_task = TaskObject {
        task_id: 78901,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Committed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some(worker.clone()),
        committed_hash: Some(compute_commitment(
            78901,
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

    let proof = b"TEE:task_id=78901,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type") && msg.contains("Fraud"))
    );

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}
