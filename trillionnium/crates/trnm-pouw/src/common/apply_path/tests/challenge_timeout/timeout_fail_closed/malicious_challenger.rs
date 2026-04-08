use super::*;

#[test]
fn timeout_rejects_inconsistent_challenged_task_missing_challenger_when_bond_exists() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 29058, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29058, &result_hash, &reveal_salt, "worker1");

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

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_inconsistent_challenged_task_noncanonical_challenger_when_bond_exists() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 29059, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29059, &result_hash, &reveal_salt, "worker1");

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

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = Some(" challenger ".into());
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_inconsistent_challenged_task_zero_bond() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 29060, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29060, &result_hash, &reveal_salt, "worker1");

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

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenge_bond = Some(0);
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_non_canonical_challenger_identity_without_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_962_5, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_5, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = Some(" challenger".into());
    let bad_ref = st.update_task(r5, bad).unwrap();

    let before_task = st.get_task(8_962_5).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("timeout must fail closed for malformed challenger identity");
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity"))
    );

    let after_task = st.get_task(8_962_5).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(after_task.challenger, before_task.challenger);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn challenged_timeout_rejects_non_canonical_challenger_identity_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_130, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_131, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_132, "alice".into(), 10).unwrap();
    let result_hash = [17u8; 32];
    let reveal_salt = [18u8; 32];
    let committed = compute_commitment(40_132, &result_hash, &reveal_salt, "worker1");
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
    malformed.challenger = Some(" challenger".into());
    let bad_ref = st.update_task(r5, malformed).unwrap();

    let before_task = st.get_task(bad_ref.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_132));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("non-canonical challenger identity must fail closed before timeout settlement");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenge metadata contains non-canonical challenger identity"
    )));

    let after_task = st.get_task(before_task.task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(
        after_task.resolve_deadline_height,
        before_task.resolve_deadline_height
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_132)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}
