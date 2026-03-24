use super::*;

#[test]
fn paused_state_rejects_zero_task_id_resolve_approval_without_side_effects() {
    // M1 micro-hardening: paused resolve flow must reject task-id zero so malformed governance
    // or replay envelopes cannot stage quorum state outside the real challenged-task boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_040);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    st.set_gov_param(98_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(0, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("task-id zero must be rejected while paused");
    assert!(
        err.contains("task id must be >= 1"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(0), None);
    assert_eq!(st.pending_resolve_first_approver(0), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}
