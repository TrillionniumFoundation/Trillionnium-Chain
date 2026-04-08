use super::*;

#[test]
fn paused_state_keeps_multi_party_resolve_quorum_and_escrow_conservation() {
    // M1 merge-gate invariant: emergency pause must not centralize resolve authority.
    // Even under pause, resolve confirmation remains 2-of-N distinct approvers and
    // custody balances stay untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 900);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_110, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert!(
        !first,
        "single approver must not finalize resolve approval while paused"
    );
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("same approver must still be rejected while paused");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(9_901, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize while paused");
    assert!(second, "second distinct approver must finalize");
    assert_eq!(st.pending_resolve_approval(9_901), Some((true, 2)));

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
