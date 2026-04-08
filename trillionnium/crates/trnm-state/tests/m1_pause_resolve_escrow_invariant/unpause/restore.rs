use super::*;

#[test]
fn paused_state_matured_resolve_authority_timelock_cannot_be_canceled_instead_of_applied() {
    // M1 micro-hardening: once a paused resolve_authority timelock has matured, governance
    // must not be able to cancel the active pending entry and thereby dodge the apply boundary.
    // The mature pending update, pause state, and custody balances must remain unchanged.
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

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before mature cancel attempt");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param_with_action(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("mature paused resolve_authority update must not be cancelable");
    assert!(
        err.contains("already active") || err.contains("must be applied"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("mature cancel rejection must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height,
        pending_before.activate_at_height
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature cancel rejection must not change currently applied authority set"
    );
    assert!(
        st.is_emergency_paused(),
        "mature cancel rejection must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_timelock_cannot_be_replaced_instead_of_applied() {
    // M1 micro-hardening: once a paused resolve_authority timelock has matured, governance
    // must not be able to replace the active pending entry and thereby move the apply boundary.
    // The mature pending update, pause state, and custody balances must remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_444);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 904);

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

    let pending_before = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should exist before mature replace attempt");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param_with_action(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-e,authority-f".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("mature paused resolve_authority update must not be replaceable");
    assert!(
        err.contains("already active") || err.contains("must be applied"),
        "unexpected error: {err}"
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("mature replace rejection must preserve pending resolve_authority update");
    assert_eq!(pending_after.key_id, pending_before.key_id);
    assert_eq!(pending_after.value, pending_before.value);
    assert_eq!(
        pending_after.activate_at_height,
        pending_before.activate_at_height
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "mature replace rejection must not change currently applied authority set"
    );
    assert!(
        st.is_emergency_paused(),
        "mature replace rejection must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_matured_resolve_authority_apply_scrubs_staged_pending_quorum() {
    // M1 micro-hardening: when a paused resolve_authority timelock reaches its apply
    // boundary, enforcing the mature value must rotate the configured authority, scrub any
    // staged quorum bound to that pending boundary, and leave pause/escrow state untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_445);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 905);

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
            9_820_1,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    assert_eq!(st.pending_resolve_approval(9_820_1), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_820_1).as_deref(),
        Some("authority-c")
    );
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let applied_pending = st
        .set_gov_param(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("mature paused resolve_authority timelock should apply");
    assert!(matches!(applied_pending, GovParamUpdateOutcome::Applied(_)));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-c,authority-d".into())
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.pending_resolve_approval(9_820_1), None);
    assert_eq!(st.pending_resolve_first_approver(9_820_1), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_820_1), None);
    assert_ne!(
        st.state_root(),
        root_with_pending,
        "applying paused resolve_authority must invalidate staged pending resolve quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "applying mature resolve_authority must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
