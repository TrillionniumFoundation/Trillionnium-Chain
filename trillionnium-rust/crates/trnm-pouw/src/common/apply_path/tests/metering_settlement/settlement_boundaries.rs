use super::*;

#[test]
fn resolve_success_with_llm_meter_bonus_pays_challenger_above_base_bounty() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_970, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_971,
        "llm_meter_challenge_success_bounty_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_972,
        "llm_meter_challenge_success_bounty_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_812u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let refund_only_baseline = 100u128;
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

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Slashed);
    assert_eq!(resolved.challenge_bond_forfeited, Some(false));
    assert!(st.balance_of("challenger") > refund_only_baseline + 1);
    assert_eq!(st.balance_of("challenger"), 102);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_success_with_llm_meter_bonus_preserves_bucket_conservation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_973, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_974,
        "llm_meter_challenge_success_bounty_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_975,
        "llm_meter_challenge_success_bounty_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_813u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let initial_sum = st.balance_of("challenger")
        + st.balance_of(&worker_stake_lock_account(task_id))
        + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let _r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();

    let final_sum = st.balance_of("challenger")
        + st.balance_of(&worker_stake_lock_account(task_id))
        + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    assert_eq!(initial_sum, final_sum);
    assert_eq!(st.balance_of("challenger"), 102);
    assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 38);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_completed_with_llm_meter_completion_bonus_pays_worker_above_stake_refund() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_976, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_977,
        "llm_meter_worker_completion_bonus_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_978,
        "llm_meter_worker_completion_bonus_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_814u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    assert_eq!(st.balance_of("worker1"), 0);
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Completed);
    assert_eq!(resolved.challenge_bond_forfeited, Some(true));
    assert_eq!(st.balance_of("worker1"), 41);
    assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 9);
}

#[test]
fn resolve_slashed_with_llm_meter_rebate_returns_worker_share_from_lock() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_979, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_980,
        "llm_meter_worker_slash_rebate_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_981,
        "llm_meter_worker_slash_rebate_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_815u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    assert_eq!(st.balance_of("worker1"), 0);
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

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

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Slashed);
    assert_eq!(resolved.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 101);
    assert_eq!(st.balance_of("worker1"), 1);
    assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 38);
}

#[test]
fn resolve_accept_uses_snapshotted_llm_meter_min_work_units_despite_governance_drift() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1000);
    st.set_gov_param_bootstrap_unchecked(
        9_982,
        "llm_meter_min_accept_work_units".into(),
        "0".into(),
    )
    .unwrap();
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 78_912;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [3u8; 32];
    let worker = "worker1".to_string();
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

    let r2 = apply_accept_task(&mut st, r1, worker.clone()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, worker.clone(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, &worker, result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_982,
        "llm_meter_min_accept_work_units".into(),
        "193".into(),
    )
    .unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Completed);
}

#[test]
fn resolve_slashed_uses_snapshotted_llm_meter_bounty_policy_despite_governance_drift() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_983, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_984, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_985,
        "llm_meter_challenge_success_bounty_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_986,
        "llm_meter_challenge_success_bounty_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_816u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    st.set_gov_param_bootstrap_unchecked(9_984, "challenge_success_bounty".into(), "0".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_985,
        "llm_meter_challenge_success_bounty_per_work_unit_num".into(),
        "0".into(),
    )
    .unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

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

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Slashed);
    assert_eq!(st.balance_of("challenger"), 102);
}
