use super::*;

#[test]
fn resolve_authority_timelock_transition_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: once resolve_authority enters a timelock transition, any
    // previously staged resolve quorum must be scrubbed immediately so stale approvals cannot
    // linger across the governance boundary in paused or unpaused operation.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_300,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_320,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let first = st
        .stage_or_confirm_resolve_approval(9_980, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first authority approval should stage successfully");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_980), Some((true, 1)));
    let root_with_pending = st.state_root();

    let replacement = st
        .set_gov_param(
            98_321,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    assert_eq!(st.pending_resolve_approval(9_980), None);
    assert_eq!(st.pending_resolve_first_approver(9_980), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_980), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "scrubbing stale pending resolve approvals must invalidate cached state root"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
}

#[test]
fn paused_state_pending_resolve_authority_conflict_keeps_original_timelock_and_pause_state() {
    // M1 micro-hardening: while paused, conflicting resolve_authority re-submission must fail
    // closed without mutating the already staged timelock entry or pause state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 777);

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
        .expect("initial resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before pause");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_161, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param(
            98_170,
            7_310,
            "resolve_authority".into(),
            "authority-e,authority-f".into(),
        )
        .expect_err("conflicting paused resolve_authority submit must stay blocked by timelock");
    assert!(
        err.contains("pending governance update exists for resolve_authority")
            || err.contains("timelock active"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("conflicting paused submit must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height, pending_before.activate_at_height,
        "paused conflicting submit must not move timelock boundary"
    );
    assert!(
        st.is_emergency_paused(),
        "paused conflicting submit must not unpause state"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused conflicting submit must not apply pending authority set early"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_authority_rotation_rejects_second_resolve_approval_without_escrow_drift() {
    // M1 micro-hardening: while paused, a rotated resolve authority set must fail closed,
    // clear the now-stale staged quorum, and leave custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_111);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 901);
    st.set_gov_param(98_111, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(
            9_901_1,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect("first paused approval stage should succeed");
    assert!(!first, "first approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_901_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_901_1).as_deref(),
        Some("authority-a")
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let rotated_err = st
        .stage_or_confirm_resolve_approval(
            9_901_1,
            1,
            true,
            "authority-c",
            "authority-a,authority-c",
        )
        .expect_err("paused authority rotation must fail closed and clear stale staged approval");
    assert!(
        rotated_err.contains("authority set changed"),
        "unexpected error: {rotated_err}"
    );
    assert!(
        st.is_emergency_paused(),
        "authority rotation failure must not unpause state"
    );
    assert_eq!(st.pending_resolve_approval(9_901_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_901_1), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
