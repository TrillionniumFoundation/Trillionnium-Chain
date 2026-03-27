use super::*;

#[test]
fn assigned_timeout_transitions_to_slashed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 500, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task_at_height(&mut st, r1, "worker1".into(), 100).unwrap();

    let before = apply_timeout(&mut st, r2.clone(), 120).unwrap_err();
    assert!(matches!(before, PouwError::InvalidTransition));

    let r3 = apply_timeout(&mut st, r2, 121).unwrap();
    let task = st.get_task(r3.id).unwrap();
    assert_eq!(task.status, TaskStatus::Slashed);
}

#[test]
fn committed_timeout_transitions_to_slashed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 501, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(501, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

    let before = apply_timeout(&mut st, r3.clone(), 120).unwrap_err();
    assert!(matches!(before, PouwError::InvalidTransition));

    let r4 = apply_timeout(&mut st, r3, 121).unwrap();
    let task = st.get_task(r4.id).unwrap();
    assert_eq!(task.status, TaskStatus::Slashed);
}

#[test]
fn challenged_timeout_transitions_to_completed() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let r1 = apply_create_task(&mut st, 777, "alice".into(), 10).unwrap();

    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(777, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 10).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 20).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        30,
    )
    .unwrap();
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

    let before = apply_timeout(&mut st, r5.clone(), 130).unwrap_err();
    assert!(matches!(before, PouwError::InvalidTransition));

    let r6 = apply_timeout(&mut st, r5, 131).unwrap();
    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(
        task.challenge_window_blocks_snapshot,
        Some(100),
        "terminal challenged tasks should retain the challenge-window snapshot for later collateral/proof audits"
    );
    assert_eq!(
        task.challenged_at_height,
        Some(30),
        "terminal challenged tasks should retain the original challenge height"
    );
    assert_eq!(
        task.challenge_deadline_height,
        Some(130),
        "terminal challenged tasks should retain the original challenge deadline"
    );
    assert_eq!(
        task.resolve_deadline_height,
        Some(230),
        "terminal challenged tasks should retain the resolve deadline that governed timeout settlement"
    );
    assert_eq!(task.challenge_bond, Some(10));
    assert_eq!(task.challenger.as_deref(), Some("challenger"));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_clears_stale_multisig_pending_approval_after_challenged_finalization() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19121, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19121, &result_hash, &reveal_salt, "worker1");

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
        210,
    )
    .unwrap();

    let before_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first multisig signer should only stage pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let r6 = apply_timeout(&mut st, r5, 311).expect("timeout should finalize challenged task");
    let task = st.get_task(r6.id).expect("timed out task must exist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.pending_resolve_first_approver(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);

    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(after_total, before_total);
}

#[test]
fn challenged_timeout_refunds_bond_and_keeps_forfeit_bucket_unchanged() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9056, "challenge_min_bond".into(), "10".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9057,
        "challenge_min_bond_bounty_bps".into(),
        "5000".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 29056, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29056, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        50,
        "challenger".into(),
        120,
    )
    .unwrap();

    let r6 = apply_timeout(&mut st, r5, 221).unwrap();
    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn challenged_timeout_default_path_remains_completed_and_refunds_bond() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 40_100, "alice".into(), 10).unwrap();
    let result_hash = [2u8; 32];
    let reveal_salt = [7u8; 32];
    let committed = compute_commitment(40_100, &result_hash, &reveal_salt, "worker1");
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

    let next = apply_timeout(&mut st, r5, 221).unwrap();
    let task = st.get_task(next.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 0);
}

#[test]
fn challenged_timeout_default_path_does_not_pay_bounty_or_touch_global_slash_treasury() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_111, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_112, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_113, "alice".into(), 10).unwrap();
    let result_hash = [3u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_113, &result_hash, &reveal_salt, "worker1");
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

    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let next = apply_timeout(&mut st, r5, 221).unwrap();
    let task = st.get_task(next.id).unwrap();

    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of("worker1"), 40);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_113)),
        0,
        "default challenged-timeout path should release task-local worker stake back to the worker"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_slash_treasury,
            "default challenged-timeout path must not pay challenge bounty or drain global slash treasury"
        );
}

#[test]
fn challenged_timeout_completed_path_does_not_pay_worker_completion_bonus_from_forfeit_pool() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_114, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        40_115,
        "llm_meter_worker_completion_bonus_per_work_unit_num".into(),
        "1".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        40_116,
        "llm_meter_worker_completion_bonus_per_work_unit_den".into(),
        "192".into(),
    )
    .unwrap();
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 9);

    let task_id = 40_117u64;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let proof = sample_llm_token_meter_receipt_json(task_id, "worker1", result_hash);
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, Some(proof), 110)
            .unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let before_worker = st.balance_of("worker1");
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_lock = st.balance_of(&worker_stake_lock_account(task_id));

    let next = apply_timeout(&mut st, r5, 221).unwrap();
    let task = st.get_task(next.id).unwrap();

    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
    assert_eq!(
        st.balance_of("worker1"),
        before_worker + before_lock,
        "challenged timeout should only release the task-local worker stake and must not top up from unrelated forfeited challenge collateral"
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit,
        "challenged timeout refund path must not spend historical forfeit funds on completion bonus settlement"
    );
}

#[test]
fn challenged_timeout_slash_path_only_moves_task_local_stake_and_never_auto_pays_bounty() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_114, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_115, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_116, "alice".into(), 10).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(40_116, &result_hash, &reveal_salt, "worker1");
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
    task.resolve_deadline_height = Some(220);
    task.status = TaskStatus::Challenged;
    task.challenge_bond_forfeited = Some(false);
    let r5 = st.update_task(r5, task).unwrap();

    let before_challenger = st.balance_of("challenger");
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_lock = st.balance_of(&worker_stake_lock_account(40_116));

    let mut task = st.get_task(r5.id).unwrap();
    task.status = TaskStatus::Slashed;
    let r6 = st.update_task(r5, task).unwrap();
    let timed_out = st.get_task(r6.id).unwrap();
    settle_worker_stake_for_terminal_state(&mut st, &timed_out).unwrap();

    assert_eq!(timed_out.status, TaskStatus::Slashed);
    assert_eq!(timed_out.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(&worker_stake_lock_account(40_116)), 0);
    assert_eq!(st.balance_of("worker1"), 0);
    assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_slash_treasury + before_lock,
            "slashed challenged-timeout settlement must only move task-local worker stake into global slash treasury"
        );
}

#[test]
fn timeout_slash_governance_key_remains_blocked_by_allowlist() {
    let mut st = seeded_state();
    let err = st
        .set_gov_param_bootstrap_unchecked(
            40_134,
            "default_slash_on_unresolved_challenge".into(),
            "true".into(),
        )
        .expect_err(
            "timeout-slash governance key should remain blocked until state allowlist is wired",
        );
    assert!(err.contains("governance key not allowed: default_slash_on_unresolved_challenge"));
    assert_eq!(unresolved_challenge_slash_on_timeout(&st).unwrap(), false);
}

#[test]
fn unresolved_challenge_slash_on_timeout_defaults_false_when_param_absent() {
    let st = seeded_state();
    assert_eq!(unresolved_challenge_slash_on_timeout(&st).unwrap(), false);
}

#[test]
fn committed_timeout_slashes_worker_economically_and_credits_treasury() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9803, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_balance("worker1", 40);

    let r1 = apply_create_task(&mut st, 19803, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(19803, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

    let r4 = apply_timeout(&mut st, r3, 121).unwrap();
    let task = st.get_task(r4.id).unwrap();
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(st.balance_of("worker1"), 0);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19803)), 0);
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);
}

#[test]
fn committed_timeout_no_double_slash_on_repeated_attempts() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9804, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_balance("worker1", 40);

    let r1 = apply_create_task(&mut st, 19804, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(19804, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

    let r4 = apply_timeout(&mut st, r3, 121).unwrap();
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);

    let err = apply_timeout(&mut st, r4, 122).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);
}

#[test]
fn challenged_timeout_clears_staged_multisig_resolve_approval_on_terminalization() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let task_id = 8_961_27;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

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
        210,
    )
    .unwrap();

    set_resolve_authority(&mut st, "authority-a,authority-b");
    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
        309,
    )
    .expect_err("first multisig resolve must stage approval before timeout finalizes");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(task_id), Some((true, 1)));

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let done = apply_timeout(&mut st, r5, 311)
        .expect("timed-out challenged task must terminalize and clear staged approval");
    let task = st.get_task(done.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.pending_resolve_approval(task_id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow - 10);
    assert_eq!(st.balance_of("challenger"), before_challenger + 10);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}
