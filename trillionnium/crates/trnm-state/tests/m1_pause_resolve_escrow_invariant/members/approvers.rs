use super::*;

#[test]
fn paused_state_rejects_case_variant_system_placeholder_approver_without_side_effects() {
    // M1 micro-hardening: emergency pause must not let a system placeholder masquerade as a
    // live resolve approver under case drift. Rejection must remain side-effect free.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 14_880);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 517);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let placeholder_case_variant = DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_917,
            1,
            true,
            &placeholder_case_variant,
            "authority-a,authority-b",
        )
        .expect_err("case-variant system placeholder approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_approver_without_side_effects() {
    // L03 boundary hardening: the exact canonical emergency_pause placeholder must be rejected
    // on the live paused resolve-approval path too, not only case-drifted aliases or restore.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_929);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 552);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_919,
            1,
            true,
            "governance.emergency_pause",
            "authority-a,authority-b",
        )
        .expect_err("exact emergency_pause placeholder approver must be rejected while paused");
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(st.pending_resolve_approval(9_919), None);
    assert_eq!(st.pending_resolve_first_approver(9_919), None);
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

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_second_approver_without_clearing_staged_quorum(
) {
    // L03 boundary hardening: once one paused resolve approval is already staged, the exact
    // emergency_pause placeholder must still be rejected as the second approver without
    // clearing the valid staged quorum or perturbing custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_931);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 994);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 554);

    st.set_gov_param(98_213, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_921, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first paused approval should stage quorum before malformed second approver");
    assert_eq!(st.pending_resolve_approval(9_921), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_921).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(
            9_921,
            1,
            true,
            "governance.emergency_pause",
            "authority-a,authority-b",
        )
        .expect_err(
            "exact emergency_pause placeholder second approver must be rejected while paused",
        );
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(
        st.pending_resolve_approval(9_921),
        Some((true, 1)),
        "rejecting malformed second approver must preserve staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_921).as_deref(),
        Some("authority-a"),
        "rejecting malformed second approver must preserve first-approver audit trail"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_921)
            .expect("staged quorum must remain after malformed second approver rejection")
            .confirmations,
        1,
        "rejecting malformed second approver must not fabricate a finalized quorum"
    );
    assert_eq!(st.state_root(), root_before);
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

#[test]
fn paused_state_pending_replacement_live_rejects_exact_emergency_pause_placeholder_second_approver_without_clearing_staged_quorum(
) {
    // L03 boundary hardening: when a replacement resolve_authority set is already timelocked,
    // the live paused approval path must still reject the exact emergency_pause placeholder as
    // a second approver, while preserving the valid staged quorum, pending timelock boundary,
    // and custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_028);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 510);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(9_936, 4, true, "authority-c", "authority-c,authority-d")
        .expect("first approval should stage against pending replacement authority");
    assert!(!staged, "single approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_936), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_936).as_deref(),
        Some("authority-c")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(
            9_936,
            4,
            true,
            "governance.emergency_pause",
            "authority-c,authority-d",
        )
        .expect_err(
            "exact emergency_pause placeholder second approver must be rejected against pending replacement authority",
        );
    assert!(err.contains("explicit non-system authority") || err.contains("approver"));

    assert_eq!(
        st.pending_resolve_approval(9_936),
        Some((true, 1)),
        "rejecting malformed second approver must preserve staged quorum"
    );
    assert_eq!(
        st.pending_resolve_first_approver(9_936).as_deref(),
        Some("authority-c"),
        "rejecting malformed second approver must preserve first-approver audit trail"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_936)
            .expect("staged quorum must remain after malformed second approver rejection")
            .confirmations,
        1,
        "rejecting malformed second approver must not fabricate a finalized quorum"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(st.state_root(), root_before);
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
