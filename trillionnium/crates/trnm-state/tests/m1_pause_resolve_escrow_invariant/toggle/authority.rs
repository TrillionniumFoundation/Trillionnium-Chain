use super::*;

#[test]
fn paused_state_rejects_reserved_system_resolve_approvers_without_side_effects() {
    // M1 boundary hardening: even while paused, staged resolve approvals must reject
    // reserved/system actors as approvers so custody aliases cannot masquerade as quorum votes.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_101);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 779);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 19);

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

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    for forbidden_approver in [
        "system",
        "Governance.Resolve_Authority",
        "TREASURY.CHALLENGE_ESCROW",
        "treasury.worker_slashes",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_810,
                1,
                true,
                forbidden_approver,
                "authority-a,authority-b",
            )
            .expect_err("reserved/system approver must be rejected while paused");
        assert!(
            err.contains("explicit non-system authority")
                || err.contains("single canonical actor id"),
            "unexpected error for {forbidden_approver}: {err}"
        );
        assert_eq!(
            st.pending_resolve_approval(9_810),
            None,
            "rejected approver must not leave staged quorum residue"
        );
        assert_eq!(st.pending_resolve_first_approver(9_810), None);
        assert_eq!(st.pending_resolve_approval_snapshot(9_810), None);
        assert_eq!(st.state_root(), root_before);
    }

    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_resolve_approval_authority_set_drift_without_side_effects() {
    // M1 boundary hardening: once governance has a configured resolve_authority set, staged
    // resolve approvals must match it exactly even while paused so callers cannot smuggle a
    // drifted approval quorum into pending resolve state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_102);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 780);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 20);

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

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(8_182, 3, true, "authority-a", "authority-a,authority-c")
        .expect_err("drifted paused resolve approval authority set must be rejected");
    assert!(err.contains("must match configured governance authority"));

    assert_eq!(st.pending_resolve_approval(8_182), None);
    assert_eq!(st.pending_resolve_first_approver(8_182), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_noncanonical_resolve_authority_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency_pause cannot be used to slip malformed
    // authority sets into resolve flow, and any rejection must be side-effect free.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 77_777);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_234);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_120, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let malformed_err = st
        .stage_or_confirm_resolve_approval(
            9_902,
            1,
            true,
            "authority-a",
            "authority-a, authority-b",
        )
        .expect_err("non-canonical authority set must fail closed while paused");
    assert!(malformed_err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_902),
        None,
        "rejected malformed authority set must not stage approvals"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_approval_accepts_case_variant_approver_spelling_without_releasing_escrow() {
    // M1 micro-hardening: stored authority-set membership is canonicalized case-insensitively
    // for approver lookup, so an approver spelling variant cannot spuriously fail closed.
    // Custody balances and staged quorum state must still remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 12_345);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 678);

    st.set_gov_param(98_149, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_906,
            1,
            false,
            "Authority-A",
            "authority-a,authority-b",
        )
        .expect("case-variant approver should match configured authority member");
    assert!(!first, "first distinct approver should only stage quorum");
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_906).as_deref(),
        Some("Authority-A"),
        "first approver spelling should be preserved for auditability"
    );

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_bare_emergency_pause_alias_approver_without_side_effects() {
    // L03 boundary hardening: the bare emergency_pause control-plane alias must stay reserved
    // on the live paused resolve-approval path too, not only the governance-prefixed placeholder.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_932);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 995);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 555);

    st.set_gov_param(98_214, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_922,
            1,
            true,
            "Emergency_Pause",
            "authority-a,authority-b",
        )
        .expect_err("bare emergency_pause alias approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_922), None);
    assert_eq!(st.pending_resolve_first_approver(9_922), None);
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
