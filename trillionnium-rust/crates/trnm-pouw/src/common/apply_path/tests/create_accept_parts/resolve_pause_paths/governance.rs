use super::*;

#[test]
fn challenged_pause_governance_downgrade_to_single_authority_clears_staged_multisig_on_unpause() {
    // Decentralization boundary: if governance downgrades resolver set to
    // single signer while paused, unpaused resolve must fail closed and wipe
    // stale staged approvals so one actor cannot inherit partial consensus.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

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
    .expect_err("first signer should stage pending multisig approval");
    assert!(matches!(stage_err, PouwError::ResolveApprovalStaged));
    assert!(matches!(
        st.pending_resolve_approval(r5.id),
        Some((false, _))
    ));

    st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    // Governance downgrade to single-signer authority must be rejected even
    // while paused; staged approvals and escrow must remain unchanged.
    let downgrade_err = st
        .set_gov_param(
            9_232,
            9_500,
            "resolve_authority".into(),
            "authority-b".into(),
        )
        .expect_err("single-signer resolve_authority must be rejected");
    assert!(
        downgrade_err.contains("at least two members"),
        "unexpected governance rejection: {downgrade_err}"
    );
    assert!(matches!(
        st.pending_resolve_approval(r5.id),
        Some((false, _))
    ));

    let before_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "false".into())
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
    .expect("distinct second signer should finalize once pause clears");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.pending_resolve_first_approver(r6.id), None);

    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Completed);
    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(after_total, before_total);
}
