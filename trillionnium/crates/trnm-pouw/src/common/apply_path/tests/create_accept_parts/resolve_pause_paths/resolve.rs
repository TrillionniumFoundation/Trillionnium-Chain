use super::*;

#[test]
fn legacy_fallback_asymmetry_keeps_challenge_deadline_and_signer_auth_intact() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9132, "challenge_window_blocks".into(), "100".into())
        .unwrap();
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 19132, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19132, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    // Simulate pre-snapshot legacy Revealed task persisted before rollout.
    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    // Increase window to governance max just before challenge.
    st.set_gov_param_bootstrap_unchecked(9132, "challenge_window_blocks".into(), "600".into())
        .unwrap();

    // Challenge admission still respects stored reveal-time deadline (<= 210).
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        210,
    )
    .unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_deadline_height, Some(210));
    assert_eq!(task.resolve_deadline_height, Some(810));

    // Resolve remains signer-bound; payload resolver cannot bypass authority check.
    let err = apply_resolve_at_height(
        &mut st,
        r5,
        true,
        "authority".into(),
        "attacker".into(),
        211,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(19132).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
}
