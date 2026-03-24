use super::*;

#[test]
fn reveal_accepts_valid_llm_token_meter_receipt_for_fraud_task() {
    let mut st = seeded_state();
    let task_id = 78_903;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

    let task = st.get_task(r4.id).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.result_hash, Some(result_hash));
    assert_eq!(task.reveal_salt, Some(reveal_salt));
    assert!(task.challenge_deadline_height.is_some());
}

#[test]
fn reveal_rejects_llm_token_meter_receipt_with_worker_mismatch_fail_closed() {
    let mut st = seeded_state();
    let task_id = 78_904;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker2", result_hash);
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("llm token meter receipt worker mismatch"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_rejects_llm_token_meter_receipt_with_output_hash_mismatch_fail_closed() {
    let mut st = seeded_state();
    let task_id = 78_905;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, [4u8; 32]);
    let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
        .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("llm token meter receipt output_hash mismatch"))
    );

    let task_after = st.get_task(r3.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Committed);
    assert!(task_after.result_hash.is_none());
    assert!(task_after.reveal_salt.is_none());
}

#[test]
fn reveal_persists_llm_token_metering_snapshot_on_task_metadata() {
    let mut st = seeded_state();
    let task_id = 78_906;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

    let task = st.get_task(r4.id).unwrap();
    let snapshot = task.metadata.unwrap().metering.unwrap();
    assert_eq!(snapshot.workload_class, LLM_INFERENCE_WORKLOAD_CLASS);
    assert_eq!(snapshot.metering_schema, LLM_TOKEN_METER_V1_SCHEMA);
    assert_eq!(snapshot.prompt_tokens, 128);
    assert_eq!(snapshot.generated_tokens, 32);
    assert_eq!(snapshot.decode_steps, 32);
    assert_eq!(snapshot.kv_bytes_moved, 4096);
    assert_eq!(snapshot.prompt_token_weight, 1);
    assert_eq!(snapshot.generated_token_weight, 1);
    assert_eq!(snapshot.decode_step_weight, 1);
    assert_eq!(snapshot.kv_byte_weight, 0);
    assert_eq!(snapshot.normalized_work_units, 192);
}

#[test]
fn reveal_snapshots_llm_token_meter_governance_policy() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9_960, "llm_meter_prompt_token_weight".into(), "2".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_961,
        "llm_meter_generated_token_weight".into(),
        "3".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_962, "llm_meter_decode_step_weight".into(), "5".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_963, "llm_meter_kv_byte_weight".into(), "7".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_964,
        "llm_meter_min_accept_work_units".into(),
        "13".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_965, "challenge_success_bounty".into(), "11".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_966,
        "llm_meter_challenge_success_bounty_per_work_unit_num".into(),
        "17".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_967,
        "llm_meter_challenge_success_bounty_per_work_unit_den".into(),
        "19".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_968,
        "llm_meter_worker_completion_bonus_per_work_unit_num".into(),
        "23".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_969,
        "llm_meter_worker_completion_bonus_per_work_unit_den".into(),
        "29".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_970,
        "llm_meter_worker_slash_rebate_per_work_unit_num".into(),
        "31".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_971,
        "llm_meter_worker_slash_rebate_per_work_unit_den".into(),
        "37".into(),
    )
    .unwrap();

    let task_id = 78_907;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

    let task = st.get_task(r4.id).unwrap();
    let snapshot = task.metadata.unwrap().metering.unwrap();
    assert_eq!(
        snapshot.policy_snapshot_version,
        CURRENT_LLM_METER_POLICY_SNAPSHOT_VERSION
    );
    assert_eq!(snapshot.prompt_token_weight, 2);
    assert_eq!(snapshot.generated_token_weight, 3);
    assert_eq!(snapshot.decode_step_weight, 5);
    assert_eq!(snapshot.kv_byte_weight, 7);
    assert_eq!(snapshot.min_accept_work_units, 13);
    assert_eq!(snapshot.challenge_success_bounty_base, 11);
    assert_eq!(snapshot.challenge_success_bounty_per_work_unit_num, 17);
    assert_eq!(snapshot.challenge_success_bounty_per_work_unit_den, 19);
    assert_eq!(snapshot.worker_completion_bonus_per_work_unit_num, 23);
    assert_eq!(snapshot.worker_completion_bonus_per_work_unit_den, 29);
    assert_eq!(snapshot.worker_slash_rebate_per_work_unit_num, 31);
    assert_eq!(snapshot.worker_slash_rebate_per_work_unit_den, 37);
    assert_eq!(
        snapshot.normalized_work_units,
        2 * 128 + 3 * 32 + 5 * 32 + 7 * 4096
    );
}

#[test]
fn challenge_rejects_tampered_llm_metering_snapshot_fail_closed() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1000);
    let task_id = 78_908;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

    let mut tampered = st.get_task(r4.id).unwrap();
    tampered
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap()
        .normalized_work_units += 1;
    let r4_bad = st.update_task(r4, tampered).unwrap();

    let err = apply_challenge(
        &mut st,
        r4_bad.clone(),
        "challenger".into(),
        10,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("normalized_work_units mismatch")));

    let task_after = st.get_task(r4_bad.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Revealed);
    assert!(task_after.challenger.is_none());
    assert!(task_after.challenge_bond.is_none());
}

#[test]
fn resolve_rejects_tampered_llm_metering_snapshot_fail_closed() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1000);
    let task_id = 78_909;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let mut tampered = st.get_task(r5.id).unwrap();
    tampered
        .metadata
        .as_mut()
        .unwrap()
        .metering
        .as_mut()
        .unwrap()
        .normalized_work_units += 1;
    let r5_bad = st.update_task(r5, tampered).unwrap();
    set_resolve_authority(&mut st, "authority,authority2");

    let err = apply_resolve(
        &mut st,
        r5_bad.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("normalized_work_units mismatch")));

    let task_after = st.get_task(r5_bad.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Challenged);
    assert_eq!(task_after.challenge_bond, Some(10));
    assert_eq!(task_after.challenger.as_deref(), Some("challenger"));
}

#[test]
fn resolve_rejects_accepting_llm_meter_below_governance_min_work_units() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1000);
    st.set_gov_param_bootstrap_unchecked(
        9_964,
        "llm_meter_min_accept_work_units".into(),
        "193".into(),
    )
    .unwrap();
    let task_id = 78_910;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    set_resolve_authority(&mut st, "authority,authority2");

    let err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("below governance minimum 193")));

    let task_after = st.get_task(r5.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Challenged);
    assert_eq!(task_after.challenge_bond, Some(10));
}

#[test]
fn resolve_allows_slashing_llm_meter_below_governance_min_work_units() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1000);
    st.set_gov_param_bootstrap_unchecked(
        9_965,
        "llm_meter_min_accept_work_units".into(),
        "193".into(),
    )
    .unwrap();
    let task_id = 78_911;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    set_resolve_authority(&mut st, "authority,authority2");
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();

    let task_after = st.get_task(r6.id).unwrap();
    assert_eq!(task_after.status, TaskStatus::Slashed);
}
