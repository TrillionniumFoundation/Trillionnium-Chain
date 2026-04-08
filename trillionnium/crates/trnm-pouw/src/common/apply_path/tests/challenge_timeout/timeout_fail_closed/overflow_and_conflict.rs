use super::*;

#[test]
fn timeout_challenged_preflight_overflow_rejects_without_status_or_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 9953, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9953, &result_hash, &reveal_salt, "worker1");
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

    st.set_balance("challenger", u128::MAX - 5);

    let err = apply_timeout(&mut st, r5, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(9953).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of("challenger"), u128::MAX - 5);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
}

#[test]
fn timeout_challenged_worker_settlement_overflow_rejects_without_partial_timeout_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 9_954, "alice".into(), 10).unwrap();
    let result_hash = [4u8; 32];
    let reveal_salt = [5u8; 32];
    let committed = compute_commitment(9_954, &result_hash, &reveal_salt, "worker1");
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

    let worker_lock = worker_stake_lock_account(9_954);
    assert_eq!(st.balance_of(&worker_lock), 1);
    st.set_balance("worker1", u128::MAX);

    let before = st.clone();
    let err = apply_timeout(&mut st, r5, 221).expect_err(
        "timeout must fail closed when terminal worker settlement would overflow worker balance",
    );
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(9_954).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
    assert_eq!(st.balance_of("worker1"), before.balance_of("worker1"));
    assert_eq!(st.balance_of(&worker_lock), before.balance_of(&worker_lock));
}

#[test]
fn timeout_version_conflict_does_not_move_funds() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 9903, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9903, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        30,
    )
    .unwrap();

    let stale_ref = r5.clone();
    let same_task = st.get_task(r5.id).unwrap();
    let _fresh_ref = st.update_task(r5, same_task).unwrap();

    let err = apply_timeout(&mut st, stale_ref, 131).unwrap_err();
    assert!(matches!(err, PouwError::VersionConflict));
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
