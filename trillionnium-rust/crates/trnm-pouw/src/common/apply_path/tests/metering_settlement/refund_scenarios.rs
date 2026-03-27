use super::*;

#[test]
fn challenge_success_bounty_rejects_slashed_task_missing_successful_challenge_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_201, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_202, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_203, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_203, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenged_at_height = None;
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_203));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task).expect_err(
        "slashed payout must fail closed without successful challenge settlement metadata",
    );
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("successful challenge settlement metadata"))
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_203)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_zero_challenge_bond_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_221, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_222, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_223, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_223, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenge_bond = Some(0);
    malformed.challenge_bond_forfeited = Some(false);
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_223));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task)
        .expect_err("challenge success bounty must fail closed for zero challenge bond metadata");
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("non-zero challenge bond metadata"))
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_223)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_blank_challenger_identity() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_223, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_224, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_225, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_225, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenge_bond_forfeited = Some(false);
    malformed.challenger = Some("   ".into());
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_225));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task)
        .expect_err("challenge success bounty must fail closed for blank challenger identity");
    assert!(matches!(err, PouwError::State(msg) if msg.contains("challenger identity")));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_225)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_noncanonical_challenger_identity() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_221, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_222, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_223, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_223, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenge_bond_forfeited = Some(false);
    malformed.challenger = Some("challenger\u{200b}".into());
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_223));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task)
        .expect_err("challenge success bounty must fail closed for malformed challenger identity");
    assert!(matches!(err, PouwError::State(msg) if msg.contains("canonical challenger identity")));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_223)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_terminal_task_missing_resolve_deadline_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_251, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_252, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_253, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_253, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenge_bond_forfeited = Some(false);
    malformed.resolve_deadline_height = None;
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_253));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task)
            .expect_err("challenge success bounty must fail closed for malformed terminal challenge timing metadata");
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("terminal challenged task missing challenge timing metadata"))
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_253)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_slashed_task_without_successful_forfeit_marker() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 50);
    st.set_gov_param_bootstrap_unchecked(40_204, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_205, "min_worker_stake".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_206, "alice".into(), 10).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(40_206, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.status = TaskStatus::Slashed;
    malformed.challenge_bond_forfeited = Some(true);
    let next = st.update_task(r5, malformed).unwrap();
    let task = st.get_task(next.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_206));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task)
        .expect_err("slashed payout must fail closed without successful challenge forfeit marker");
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("successful challenge settlement metadata"))
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_206)),
        before_lock
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenge_success_bounty_rejects_underfunded_task_local_slashable_stake() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 1);
    st.set_gov_param_bootstrap_unchecked(40_211, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_212, "min_worker_stake".into(), "1".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 40_213, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(40_213, &result_hash, &reveal_salt, "worker1");
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
    let lock_account = worker_stake_lock_account(40_213);
    st.debit_balance(&lock_account, 1).unwrap();

    let before_challenger = st.balance_of("challenger");
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = maybe_pay_challenge_success_bounty(&mut st, &task).expect_err(
        "challenge success bounty must fail closed when task-local slashable stake is depleted",
    );
    assert!(matches!(err, PouwError::State(msg) if msg.contains("task-local slashable stake")));
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of(&lock_account), 0);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );
}
