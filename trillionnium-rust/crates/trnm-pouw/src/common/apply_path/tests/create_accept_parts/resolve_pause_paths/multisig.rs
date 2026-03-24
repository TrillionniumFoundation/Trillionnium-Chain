use super::*;

#[test]
fn challenged_multisig_resolve_rejects_while_paused_without_escrow_drift() {
    // Safety boundary: emergency pause must fail-closed before terminal multisig
    // resolve settlement so staged approvals cannot move escrow funds until unpaused.
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

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first multisig signer should only stage pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

    st.set_gov_param(9_224, 7_999, "emergency_pause".into(), "true".into())
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
        "authority-b".into(),
        "authority-b".into(),
        212,
    )
    .expect_err("emergency pause must freeze multisig resolve settlement path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

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

    st.set_gov_param(9_225, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority-b".into(),
        "authority-b".into(),
        212,
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
fn challenged_multisig_resolve_rejects_first_approval_while_paused_without_staging_or_escrow_drift()
{
    // Safety boundary: emergency pause must fail closed before any multisig
    // approval staging, so no partial authority state is recorded while paused.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19_223_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_1, &result_hash, &reveal_salt, "worker1");

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

    let before_task = st.get_task(r5.id).expect("challenged task must persist");
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_total = before_challenger + before_escrow + before_forfeit;

    let paused_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("emergency pause must reject first multisig approval staging");
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
    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(after_total, before_total);

    st.set_gov_param(9_227, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first signer should stage pending approval once pause clears");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
}

#[test]
fn challenged_pause_preserves_pre_staged_multisig_approval_until_unpaused_consensus() {
    // Safety boundary: emergency pause must reject terminal resolve attempts
    // without mutating previously staged multisig approval state.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b,authority-c");

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

    let stage_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first signer should only stage pending multisig approval");
    assert!(matches!(stage_err, PouwError::ResolveApprovalStaged));
    let staged_before_pause = st.pending_resolve_approval(r5.id);
    assert!(matches!(staged_before_pause, Some((false, _))));
    let before_paused_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(9_228, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        false,
        "authority-b".into(),
        "authority-b".into(),
        212,
    )
    .expect_err("pause must reject resolve without mutating staged approvals");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), staged_before_pause);
    let after_paused_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(after_paused_total, before_paused_total);

    st.set_gov_param(9_229, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority-b".into(),
        "authority-b".into(),
        213,
    )
    .expect("second distinct signer should finalize once pause clears");

    let task = st.get_task(r6.id).expect("resolved task must exist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(st.pending_resolve_approval(r6.id), None);
}
