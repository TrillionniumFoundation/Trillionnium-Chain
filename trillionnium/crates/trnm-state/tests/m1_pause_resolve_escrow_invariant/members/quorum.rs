use super::*;

#[test]
fn paused_state_rejects_single_member_resolve_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency_pause cannot degrade resolve approval into
    // a single-party control path. Singleton authority sets must fail closed and keep
    // escrow custody untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_880);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 120);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_125, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let err = st
        .stage_or_confirm_resolve_approval(9_904, 1, true, "authority-a", "authority-a")
        .expect_err("singleton resolve authority set must be rejected while paused");
    assert!(err.contains("at least two members"));

    assert_eq!(
        st.pending_resolve_approval(9_904),
        None,
        "singleton authority set rejection must not stage pending approvals"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_approval_keeps_staged_quorum_across_member_reordering() {
    // M1 micro-hardening: a replay that only reorders the same authority members must not
    // clear staged paused resolve quorum or force governance to restart approvals.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_450);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 443);

    st.set_gov_param(98_148, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_905_1,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first approval stage should succeed while paused");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_905_1), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(
            9_905_1,
            1,
            true,
            "authority-b",
            "authority-b,authority-a",
        )
        .expect("member reordering should preserve staged quorum while paused");
    assert!(second, "second distinct approver should finalize quorum");
    assert_eq!(st.pending_resolve_approval(9_905_1), Some((true, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_905_1).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
