use super::*;

#[test]
fn malformed_challenged_invariant_failure_rejects_early_without_status_or_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39001, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39001, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    set_resolve_authority(&mut st, "authority");
    let err = apply_resolve(
        &mut st,
        bad_ref,
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(39001).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}
