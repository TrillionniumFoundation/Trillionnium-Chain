use super::*;

#[test]
fn challenged_multisig_first_approval_rejects_while_paused_without_staging_or_escrow_drift() {
    // Safety boundary: emergency pause must also block first-signer staging so
    // challenged escrow paths cannot accumulate latent approvals while paused.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19_222, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_222, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_221, 7_999, "emergency_pause".into(), "true".into())
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
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("emergency pause must block first multisig resolve approval staging");
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
}

#[test]
fn challenged_multisig_first_approval_can_stage_after_unpause_without_escrow_drift() {
    // Safety boundary: pause should block first-approval staging, but governance
    // unpause must restore the exact same staging path without mutating custody.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19_223, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_226, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_paused_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let paused_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("pause must block first multisig staging");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), None);

    st.set_gov_param(9_227, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first multisig signer should stage once unpaused");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert!(matches!(
        st.pending_resolve_approval(r5.id),
        Some((false, 1))
    ));

    let r6 = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority-b".into(),
        "authority-b".into(),
        212,
    )
    .expect("second multisig signer should finalize once unpaused");
    let task = st.get_task(r6.id).expect("resolved task must exist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(true));
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);

    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(after_total, before_paused_total);
}
