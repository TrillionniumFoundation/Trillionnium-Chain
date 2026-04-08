use super::*;

#[test]
fn pause_toggle_rejects_wrong_key_id_without_mutating_escrow_or_resolve_state() {
    // M1 merge-gate invariant: emergency_pause has a fixed governance key id boundary.
    // Wrong key-id writes must fail closed and be side-effect free for custody + resolve flow.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_600);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 700);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_130, 7_998, "emergency_pause".into(), "true".into())
        .expect_err("emergency_pause must reject non-canonical key id");
    assert!(err.contains("governance key id mismatch"));
    assert!(!st.is_emergency_paused());

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.pending_resolve_approval(9_903), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn pause_toggle_rejects_non_boolean_value_without_releasing_escrow_or_centralizing_resolve_flow() {
    // M1 merge-gate invariant: emergency_pause is a strict boolean safety boundary.
    // Invalid values must fail closed while preserving custody balances and any staged
    // multi-party resolve approvals.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_900);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 333);

    st.stage_or_confirm_resolve_approval(9_905, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed before malformed pause write");
    assert_eq!(st.pending_resolve_approval(9_905), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_140, 7_999, "emergency_pause".into(), "TRUE".into())
        .expect_err("emergency_pause must reject non-canonical boolean values");
    assert!(err.contains("expected strict bool 'true' or 'false'"));
    assert!(!st.is_emergency_paused());

    assert_eq!(
        st.pending_resolve_approval(9_905),
        Some((true, 1)),
        "invalid pause write must not mutate staged resolve quorum"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
