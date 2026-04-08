use super::*;

#[test]
fn slashed_terminal_settlement_without_explicit_bounty_payout_only_credits_global_slash_treasury() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_091, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_092, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_093, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_093, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut task = st.get_task(r5.id).unwrap();
    task.status = TaskStatus::Slashed;
    task.challenge_bond_forfeited = Some(false);
    let next = st.update_task(r5, task).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    settle_worker_stake_for_terminal_state(&mut st, &task).unwrap();

    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury + 50
    );
    assert_eq!(st.balance_of(&worker_stake_lock_account(40_093)), 0);
    assert_eq!(st.balance_of("worker1"), 0);
}

#[test]
fn slashed_terminal_settlement_pays_challenge_bounty_from_task_local_worker_lock_when_explicitly_invoked(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_101, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_102, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_103, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_103, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    // Simulate a slashed terminal state directly and assert the L05 economic
    // boundary: challenger reward is a distinct path that must be invoked
    // explicitly and must come only from task-local slash principal.
    let mut task = st.get_task(r5.id).unwrap();
    task.status = TaskStatus::Slashed;
    task.challenge_bond_forfeited = Some(false);
    let next = st.update_task(r5, task).unwrap();
    let task = st.get_task(next.id).unwrap();
    let paid = maybe_pay_challenge_success_bounty(&mut st, &task).unwrap();
    assert_eq!(paid, 1);
    settle_worker_stake_for_terminal_state(&mut st, &task).unwrap();

    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 91);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 49);
    assert_eq!(st.balance_of(&worker_stake_lock_account(40_103)), 0);
    assert_eq!(st.balance_of("worker1"), 0);
}

#[test]
fn slashed_terminal_settlement_zero_configured_challenge_bounty_keeps_entire_task_local_slash_in_treasury(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_131, "challenge_success_bounty".into(), "0".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_132, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_133, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_133, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut task = st.get_task(r5.id).unwrap();
    task.status = TaskStatus::Slashed;
    task.challenge_bond_forfeited = Some(false);
    let next = st.update_task(r5, task).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let paid = maybe_pay_challenge_success_bounty(&mut st, &task).unwrap();
    assert_eq!(paid, 0);
    settle_worker_stake_for_terminal_state(&mut st, &task).unwrap();

    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury + 50
    );
    assert_eq!(st.balance_of(&worker_stake_lock_account(40_133)), 0);
    assert_eq!(st.balance_of("worker1"), 0);
}

#[test]
fn challenge_success_bounty_rejects_newline_tainted_challenger_identity_without_lock_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_141, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_142, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_143, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_143, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut task = st.get_task(r5.id).unwrap();
    task.status = TaskStatus::Slashed;
    task.challenge_bond_forfeited = Some(false);
    task.challenger = Some("challenger\n".into());
    let next = st.update_task(r5, task).unwrap();
    let task = st.get_task(next.id).unwrap();
    let lock_account = worker_stake_lock_account(40_143);
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&lock_account);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task).expect_err(
        "challenge success bounty must fail closed for newline-tainted challenger identity",
    );
    assert!(matches!(err, PouwError::State(msg) if msg.contains("canonical challenger identity")));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of(&lock_account), before_lock);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}
