use super::*;

#[test]
fn zk_reveal_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 802, "alice".into(), 10).unwrap();

    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(802, &result_hash, &reveal_salt, &worker);
    let committed_task = TaskObject {
        task_id: 802,
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
    let r2 = st.update_task(r1, committed_task).unwrap();

    // Case-variant duplicate proof_type binding must fail closed.
    let proof = b"ZK:task_id=802,worker=worker1,proof_type=zk,Proof_Type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
    let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate proof_type binding")));

    let task_after = st.get_task(r2.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
}

#[test]

fn tee_proof_without_crypto_backend_rejects_reveal_and_preserves_committed_state() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7001, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(7001, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // TEE proof envelope must bind task_id/worker/proof_type.
    let proof = b"TEE:task_id=7001,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
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
fn tee_proof_accepts_uppercase_hex_prefix_in_result_hash_binding() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7701, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [0xabu8; 32];
    let reveal_salt = [3u8; 32];
    let committed = compute_commitment(7701, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Accept canonical envelope tuple when result_hash uses uppercase 0X hex prefix.
    let proof = b"TEE:task_id=7701,worker=worker1,proof_type=tee,result_hash=0XABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB,quote=QUOTE_XYZ".to_vec();
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
fn tee_proof_accepts_uppercase_proof_type_binding() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 7702, "alice".into(), 10).unwrap();

    let mut task = st.get_task(r1.id).unwrap();
    task.proof_type = ProofType::Tee;
    let r1_updated = st.update_task(r1, task).unwrap();

    let result_hash = [0xacu8; 32];
    let reveal_salt = [5u8; 32];
    let committed = compute_commitment(7702, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // Accept canonical envelope tuple when proof_type value uses uppercase alias.
    let proof = b"TEE:task_id=7702,worker=worker1,proof_type=TEE,result_hash=ACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACAC,quote=QUOTE_XYZ".to_vec();
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
