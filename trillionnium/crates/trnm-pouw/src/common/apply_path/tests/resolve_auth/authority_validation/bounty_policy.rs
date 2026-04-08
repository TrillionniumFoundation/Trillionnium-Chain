use super::*;

#[test]
fn resolve_slash_pays_success_bounty_only_from_task_lock_not_global_slash_treasury() {
    let mut st = seeded_state();
    st.set_balance("worker1", 10);
    st.set_balance("challenger", 1_000);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 77);
    st.set_gov_param_bootstrap_unchecked(9_989, "min_worker_stake".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_990, "challenge_success_bounty".into(), "1".into())
        .unwrap();

    let task_id = 21_499;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let lock_account = worker_stake_lock_account(task_id);
    st.debit_balance(&lock_account, 1).unwrap();
    st.credit_balance("drain", 1).unwrap();
    assert_eq!(st.balance_of(&lock_account), 0);

    set_resolve_authority(&mut st, "authority");

    let challenger_before = st.balance_of("challenger");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let slash_treasury_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority".into(),
            "authority".into(),
            1,
        )
        .expect_err("resolve must fail closed when configured bounty exceeds remaining task-local slashable stake");

    assert!(
        matches!(err, PouwError::State(_)) || matches!(err, PouwError::Unauthorized),
        "unexpected resolve failure variant: {err:?}"
    );
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(
        st.balance_of("challenger"),
        challenger_before,
        "challenger balance must remain unchanged when resolve settlement aborts"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        slash_treasury_before,
        "challenge success bounty must not fall back to global worker slash treasury"
    );
}

#[test]
fn resolve_success_gives_challenger_more_than_bond_refund_baseline() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 891, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(891, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

    let refund_only_baseline = 100u128;
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

    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.status, TaskStatus::Slashed);
    assert_eq!(resolved.challenge_bond_forfeited, Some(false));
    assert!(st.balance_of("challenger") > refund_only_baseline);
    assert_eq!(st.balance_of("challenger"), 101);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_success_conserves_challenge_related_buckets_with_explicit_bounty_flow() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9810, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29810u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
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
    assert_eq!(st.balance_of("challenger"), 101);
    assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 39);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_completed_uses_snapshotted_worker_bonus_policy_despite_governance_drift() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9_987, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_988,
        "llm_meter_worker_completion_bonus_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_989,
        "llm_meter_worker_completion_bonus_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance("worker1", 40);
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 29_817u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9_988,
        "llm_meter_worker_completion_bonus_per_work_unit_num".into(),
        "0".into(),
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
    assert_eq!(st.balance_of("worker1"), 41);
}
