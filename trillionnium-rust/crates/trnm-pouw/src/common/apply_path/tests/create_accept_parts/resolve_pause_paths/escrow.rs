use super::*;

#[test]
fn challenged_single_authority_resolve_rejects_while_paused_without_escrow_drift() {
    // Safety boundary: emergency pause must fail-closed for single-authority
    // resolve so escrow settlement remains frozen regardless of multisig mode.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 19_223_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_2, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_228, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(r5.id).expect("challenged task must persist");
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let paused_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
        211,
    )
    .expect_err("emergency pause must freeze single-authority resolve settlement path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), None);

    let after_paused_task = st
        .get_task(r5.id)
        .expect("task must remain unchanged while paused");
    assert_eq!(after_paused_task.status, before_task.status);
    assert_eq!(
        after_paused_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_229, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
        211,
    )
    .expect_err("first resolver should stage once emergency pause clears");
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority2".into(),
        "authority2".into(),
        211,
    )
    .expect("multisig resolve should settle after emergency pause clears");
    let task = st.get_task(r6.id).expect("resolved task must exist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_total = before_challenger + before_escrow + before_forfeit;
    assert_eq!(after_total, before_total);
}

#[test]
fn challenged_single_authority_slash_resolve_rejects_while_paused_without_balance_drift() {
    // Safety boundary: emergency pause must also freeze slash=true resolution
    // so authority cannot trigger worker-forfeit escrow exits while paused.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 19_223_3, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_3, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(r5.id).expect("challenged task must persist");
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let paused_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
        211,
    )
    .expect_err("emergency pause must freeze slash resolve settlement path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));

    let after_paused_task = st
        .get_task(r5.id)
        .expect("task must remain unchanged while paused");
    assert_eq!(after_paused_task.status, before_task.status);
    assert_eq!(
        after_paused_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
        211,
    )
    .expect_err("first resolver should stage once emergency pause clears");
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve_at_height(
        &mut st,
        r5,
        true,
        "authority2".into(),
        "authority2".into(),
        211,
    )
    .expect("multisig slash resolve should settle after emergency pause clears");
    let task = st.get_task(r6.id).expect("resolved task must exist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
}
