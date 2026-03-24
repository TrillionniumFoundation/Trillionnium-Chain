use super::*;

#[test]
fn paused_state_pending_resolve_authority_cancel_scrubs_staged_quorum_without_escrow_drift() {
    // M1 micro-hardening: while paused, cancelling a not-yet-mature resolve_authority
    // timelock is still a governance boundary transition. It must clear any staged quorum
    // bound to that pending authority set, preserve escrow balances, and keep pause enabled.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_333);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_819_1,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    assert_eq!(st.pending_resolve_approval(9_819_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_819_1).as_deref(),
        Some("authority-c")
    );
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let cancelled = st
        .set_gov_param_with_action(
            98_190,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("paused pending resolve_authority update should cancel before maturity");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused pre-maturity cancel must keep configured resolve authority unchanged"
    );
    assert_eq!(st.pending_resolve_approval(9_819_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_819_1), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_819_1), None);
    assert_ne!(
        st.state_root(),
        root_with_pending,
        "paused cancel of pending resolve_authority must invalidate staged pending resolve quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "paused pre-maturity cancel must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_resolve_decision_mismatch_without_escrow_or_quorum_mutation() {
    // M1 micro-hardening: while paused, a conflicting slash/no-slash confirmation must fail
    // closed and keep both the staged quorum and custody balances unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_222);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 902);
    st.set_gov_param(98_112, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_2,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_2), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_2).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let mismatch_err = st
        .stage_or_confirm_resolve_approval(
            9_901_2,
            1,
            false,
            "authority-b",
            "authority-a,authority-b",
        )
        .expect_err("paused resolve decision mismatch must fail closed");
    assert!(
        mismatch_err.contains("decision mismatch"),
        "unexpected error: {mismatch_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "decision mismatch must not unpause state"
    );
    assert_eq!(st.pending_resolve_approval(9_901_2), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_2).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
