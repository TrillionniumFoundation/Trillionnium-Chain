use super::*;

#[test]
fn challenged_resolve_case_drift_duplicate_authority_config_is_masked_by_pause_without_escrow_drift(
) {
    // Safety boundary: emergency pause must fail before case-drift duplicate
    // authority validation so malformed governance config cannot leak resolver
    // checks while challenged escrow paths are frozen.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "Authority,authority");

    let r1 = apply_create_task(&mut st, 19_223_4, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_4, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_232, 7_999, "emergency_pause".into(), "true".into())
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
    .expect_err("pause must mask case-drift duplicate-authority resolver validation");
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

    st.set_gov_param(9_233, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let duplicate_err = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority".into(),
        "authority".into(),
        212,
    )
    .expect_err("case-drift duplicate resolver config should be rejected after unpause");
    assert!(matches!(duplicate_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn challenged_resolve_exact_duplicate_authority_config_is_masked_by_pause_without_escrow_drift() {
    // Safety boundary: emergency pause must fail before duplicate-authority
    // validation so paused challenged escrow paths do not leak governance
    // misconfiguration details or mutate custodial balances.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority");

    let r1 = apply_create_task(&mut st, 19_223_4_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_4_2, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_232_1, 7_999, "emergency_pause".into(), "true".into())
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
    .expect_err("pause must mask duplicate-authority resolver validation");
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

    st.set_gov_param(9_232_2, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let duplicate_err = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority".into(),
        "authority".into(),
        212,
    )
    .expect_err("duplicate resolver config should be rejected after unpause");
    assert!(matches!(duplicate_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn challenged_resolve_escrow_authority_overlap_is_masked_by_pause_without_escrow_drift() {
    // Safety boundary: emergency pause must fail closed before resolver/escrow
    // overlap checks so paused challenged flows cannot leak authority validation
    // behavior or mutate custodial balances.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, &format!("{},authority2", CHALLENGE_ESCROW_ACCOUNT));

    let r1 = apply_create_task(&mut st, 19_223_5, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_223_5, &result_hash, &reveal_salt, "worker1");

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

    st.set_gov_param(9_234, 7_999, "emergency_pause".into(), "true".into())
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
        "authority2".into(),
        "authority2".into(),
        211,
    )
    .expect_err("pause must mask escrow-authority overlap validation");
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

    st.set_gov_param(9_235, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let overlap_err = apply_resolve_at_height(
        &mut st,
        r5,
        false,
        "authority2".into(),
        "authority2".into(),
        212,
    )
    .expect_err("escrow-authority overlap config should be rejected after unpause");
    assert!(matches!(overlap_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
