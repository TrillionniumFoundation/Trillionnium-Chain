use super::*;

#[test]
fn paused_state_rejects_resolve_task_version_drift_and_clears_stale_quorum_without_escrow_drift() {
    // M1 micro-hardening: while paused, a changed challenged-task version must fail closed,
    // clear the stale staged quorum, and leave custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_223);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);
    st.set_gov_param(98_113, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_3,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_3), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_3).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let version_err = st
        .stage_or_confirm_resolve_approval(
            9_901_3,
            2,
            true,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect_err("paused resolve task version drift must fail closed");
    assert!(
        version_err.contains("task version changed"),
        "unexpected error: {version_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "task version drift must not unpause state"
    );
    assert_eq!(
        st.pending_resolve_approval(9_901_3),
        None,
        "task version drift must clear stale staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_901_3),
        None,
        "task version drift must clear stale first-approver audit trail"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
