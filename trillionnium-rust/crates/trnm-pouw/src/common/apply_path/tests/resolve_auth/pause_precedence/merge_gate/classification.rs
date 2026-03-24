use super::*;


#[test]
fn resolve_reopens_after_emergency_pause_clears_with_single_settlement() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_964, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_964, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_204, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("resolve must stay frozen while emergency pause is active");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 90);

    st.set_gov_param(9_205, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("first resolver should stage once emergency pause clears");
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into())
        .expect("resolve must reopen after emergency pause is cleared");
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.challenge_bond_forfeited, Some(true));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
    assert_eq!(st.balance_of("challenger"), 90);
}
#[test]
fn resolve_pause_toggle_preserves_challenge_funds_conservation() {
    // Merge-gate hardening: emergency pause must freeze terminal settlement while
    // preserving end-to-end challenge-fund conservation across challenger/escrow/forfeit.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let total_funds = |st: &StateStore| {
        st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    };

    let baseline_total = total_funds(&st);
    assert_eq!(baseline_total, 100);

    let r1 = apply_create_task(&mut st, 8_964_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_964_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    assert_eq!(total_funds(&st), baseline_total);

    st.set_gov_param(9_214_1, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("resolve must stay frozen while emergency pause is active");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(total_funds(&st), baseline_total);

    st.set_gov_param(9_214_2, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("first multisig member must stage resolve after pause clears");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(total_funds(&st), baseline_total);

    let done = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
        .expect("second multisig member must finalize resolve after pause clears");
    let task = st.get_task(done.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(true));
    assert_eq!(total_funds(&st), baseline_total);
}
