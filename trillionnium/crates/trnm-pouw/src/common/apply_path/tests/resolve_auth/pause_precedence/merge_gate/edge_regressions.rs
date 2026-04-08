use super::*;

#[test]
fn resolve_multisig_staging_persists_while_paused_then_single_authority_rotation_clears_after_unpause(
) {
    // Safety boundary: emergency pause check must execute before stale-staging
    // cleanup so no pending multisig approval state is mutated while paused.
    // After unpause, the single-authority downgrade path should still clear
    // stale staging fail-closed before any terminal escrow settlement.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig signer should only stage pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());
    set_resolve_authority(&mut st, "authority-a");

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("pause must reject resolve before stale staging cleanup");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a,authority-b".into(),
    )
    .expect_err(
        "duplicate signer replay must leave paused-staged multisig approval intact after unpause",
    );
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect(
        "second multisig signer should settle once unpaused after singleton downgrade is rejected",
    );
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.pending_resolve_first_approver(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_emergency_pause_precedes_deadline_checks_without_escrow_mutation() {
    // Merge-gate hardening: pause must fail-closed before resolve-deadline checks,
    // so challenged escrow paths do not leak timing-policy outcomes while frozen.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_961_25, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_25, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        100,
    )
    .unwrap();

    let task_before_pause = st.get_task(r5.id).unwrap();
    let resolve_deadline = task_before_pause
        .resolve_deadline_height
        .expect("challenge must set resolve deadline");

    st.set_gov_param(9_201_25, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve_at_height(
        &mut st,
        r5,
        true,
        "authority".into(),
        "authority".into(),
        resolve_deadline.saturating_add(1),
    )
    .expect_err("pause must mask deadline-check result and freeze challenged settlement");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_25).unwrap();
    assert_eq!(after_task.status, task_before_pause.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        task_before_pause.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
