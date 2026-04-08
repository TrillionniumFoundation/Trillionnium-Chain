use super::*;

#[test]
fn paused_state_rejects_case_variant_resolve_authority_placeholder_update_without_side_effects() {
    // M1 micro-hardening: the governance entrypoint must keep placeholder authority aliases
    // fail-closed under case drift even while paused, without staging a deferred update or
    // perturbing custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_100);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 778);

    st.set_gov_param(98_159, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,Governance.Resolve_Authority".into(),
        )
        .expect_err("case-variant placeholder member must be rejected at governance entrypoint");
    assert!(
        err.contains("placeholder authority") || err.contains("governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        None,
        "rejected placeholder update must not stage or apply a resolve authority value"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_system_or_treasury_resolve_authority_members_without_side_effects() {
    // M1 boundary hardening: paused governance must keep reserved/system custody identities out
    // of resolve_authority updates so corrupted aliases cannot be smuggled into approval sets.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_101);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 779);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 19);

    st.set_gov_param(98_159, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    for malformed_value in [
        "authority-a,System",
        "authority-a,TREASURY.CHALLENGE_ESCROW",
        "authority-a,treasury.worker_slashes",
    ] {
        let err = st
            .set_gov_param(
                98_160,
                7_310,
                "resolve_authority".into(),
                malformed_value.into(),
            )
            .expect_err("reserved/system members must be rejected at governance entrypoint");
        assert!(
            err.contains("reserved system authority")
                || err.contains("treasury custody accounts")
                || err.contains("governance value"),
            "unexpected error for {malformed_value}: {err}"
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            None,
            "rejected paused governance update must not leave pending residue"
        );
        assert_eq!(st.gov_param_string("resolve_authority"), None);
    }

    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}
