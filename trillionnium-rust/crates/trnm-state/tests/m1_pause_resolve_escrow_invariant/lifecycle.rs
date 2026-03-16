use super::*;

#[test]
fn paused_cancel_resolve_authority_timelock_keeps_pause_boundary_and_escrow_conservation() {
    // M1 micro-hardening: cancel path for sensitive resolve_authority must remain
    // side-effect free for pause state and custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 700);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_198, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let scheduled = st
        .set_gov_param(
            98_199,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("resolve_authority should schedule while paused");
    assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));
    assert!(st.pending_gov_update("resolve_authority").is_some());

    let cancelled = st
        .set_gov_param_with_action(
            98_200,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("cancel should remove pending resolve_authority update");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.is_emergency_paused());
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_replace_resolve_authority_timelock_keeps_pause_boundary_and_escrow_conservation() {
    // M1 micro-hardening: replacing a pending resolve_authority update while paused must
    // not leak custody balances or unset emergency pause, and must keep timelock active.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 61_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 900);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_201, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let scheduled = st
        .set_gov_param(
            98_202,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("resolve_authority should schedule while paused");
    let old_activate_at = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected scheduled outcome, got {other:?}"),
    };

    let replaced = st
        .set_gov_param_with_action(
            98_203,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-c".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace should reschedule pending resolve_authority update");
    let new_activate_at = match replaced {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected scheduled replacement, got {other:?}"),
    };

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replace must keep a pending update");
    assert_eq!(pending.value, "authority-a,authority-c");
    assert_eq!(pending.activate_at_height, new_activate_at);
    assert!(new_activate_at > old_activate_at);

    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn canonical_unpause_keeps_staged_multi_party_resolve_quorum_and_escrow_conservation() {
    // M1 merge-gate invariant: emergency pause exit with canonical key/value must only
    // toggle pause state. It must not centralize/clear a staged multi-party resolve quorum
    // or mutate custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 62_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 920);

    st.set_gov_param(98_204, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_917, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_917), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_205, 7_999, "emergency_pause".into(), "false".into())
        .expect("canonical unpause must apply immediately");

    assert!(!st.is_emergency_paused());
    assert_eq!(st.pending_resolve_approval(9_917), Some((true, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn clearing_staged_resolve_quorum_is_idempotent_and_side_effect_free_under_pause() {
    // M1 micro-hardening: stale multisig staging cleanup (used during authority
    // downgrade/rotation fail-closed paths) must be idempotent, preserve pause,
    // and keep escrow/treasury custody balances exactly conserved.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 63_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 930);

    st.set_gov_param(98_206, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.stage_or_confirm_resolve_approval(9_918, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_918), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_918).as_deref(),
        Some("authority-a")
    );

    st.clear_pending_resolve_approval(9_918);
    st.clear_pending_resolve_approval(9_918);

    assert_eq!(st.pending_resolve_approval(9_918), None);
    assert_eq!(st.pending_resolve_first_approver(9_918), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn unpause_does_not_bypass_pending_resolve_authority_timelock_or_escrow_conservation() {
    // M1 micro-hardening: leaving emergency pause must not auto-apply a staged
    // resolve_authority update. Governance timelock + custody conservation stay intact.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 64_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 940);

    st.set_gov_param(98_207, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let resolve_before = st.gov_param_string("resolve_authority");
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let scheduled = st
        .set_gov_param(
            98_208,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-c".into(),
        )
        .expect("resolve_authority should schedule while paused");
    assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));

    st.set_gov_param(98_209, 7_999, "emergency_pause".into(), "false".into())
        .expect("canonical unpause must apply immediately");
    assert!(!st.is_emergency_paused());

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("unpause must not auto-apply pending resolve_authority");
    assert_eq!(pending.value, "authority-a,authority-c");
    assert_eq!(st.gov_param_string("resolve_authority"), resolve_before);

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
