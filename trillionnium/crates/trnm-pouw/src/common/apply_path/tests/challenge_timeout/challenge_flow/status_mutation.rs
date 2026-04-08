use super::*;

#[test]
fn challenge_replay_attempt_after_challenged_state_is_rejected_without_double_escrow_debit() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_996, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_996, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let challenger_after_first_challenge = st.balance_of("challenger");
    let escrow_after_first_challenge = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeit_after_first_challenge = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err =
        apply_challenge(&mut st, r5, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));

    assert_eq!(
        st.balance_of("challenger"),
        challenger_after_first_challenge
    );
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        escrow_after_first_challenge
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeit_after_first_challenge
    );
}

#[test]
fn challenge_preflight_overflow_rejects_without_status_or_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, u128::MAX - 5);

    let r1 = apply_create_task(&mut st, 9951, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9951, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err =
        apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(9951).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), u128::MAX - 5);
}

#[test]
fn challenge_version_conflict_does_not_move_funds() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 9901, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9901, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let stale_ref = r4.clone();
    let same_task = st.get_task(r4.id).unwrap();
    let _fresh_ref = st.update_task(r4, same_task).unwrap();

    let err = apply_challenge(
        &mut st,
        stale_ref,
        "challenger".into(),
        10,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::VersionConflict));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
