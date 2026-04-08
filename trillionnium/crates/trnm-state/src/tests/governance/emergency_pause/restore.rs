use super::*;

#[test]
fn emergency_pause_cancel_scrubs_stale_pending_entry_even_when_unsupported() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: non-sensitive emergency_pause should never have
    // timelocked pending state; even unsupported Cancel attempts must scrub stale entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_650,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unsupported cancel must still scrub stale pending emergency_pause entries"
    );
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_skips_value_validation_but_stays_side_effect_free() {
    let mut st = StateStore::new();

    // Merge-gate guard: Cancel keeps parser bypass semantics (no bool validation) but must
    // remain side-effect free beyond stale pending cleanup.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_888,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            7_999,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        !cancel_err.contains("invalid governance value"),
        "cancel path must not attempt value parsing for emergency_pause"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_scrubs_stale_pending_entry_without_mutating_live_pause_binding() {
    let mut st = StateStore::new();

    st.set_gov_param(8_699, 7_999, "emergency_pause".into(), "true".into())
        .expect("baseline pause=true should apply immediately");
    let live_before = st.gov_param("emergency_pause").cloned();
    assert!(st.is_emergency_paused());

    // Corrupt/legacy state simulation: even while the live pause guard is already active,
    // unsupported cancel should only scrub stale queued residue and must not mutate the
    // canonical emergency_pause object or unpause the store.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 88_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_700,
            7_999,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel remains unsupported for non-sensitive emergency_pause");
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        !cancel_err.contains("invalid governance value"),
        "cancel path must keep parser-bypass semantics for emergency_pause"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unsupported cancel must still scrub stale pending emergency_pause entries"
    );
    assert!(
        st.is_emergency_paused(),
        "unsupported cancel must not unpause the live emergency brake"
    );
    assert_eq!(
        st.gov_param("emergency_pause").cloned(),
        live_before,
        "unsupported cancel must preserve the canonical live emergency_pause object"
    );
}

#[test]
fn emergency_pause_checked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // but if a stale pending entry exists, checked-path apply must scrub it.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param(8_700, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "stale pending entry must be removed for non-sensitive emergency_pause"
    );
}

#[test]
fn emergency_pause_unchecked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // and unchecked-path writes must still scrub stale pending entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_888,
        },
    );

    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked emergency_pause apply must remove stale pending entry"
    );
}

#[test]
fn emergency_pause_unchecked_noop_is_idempotent_and_clears_stale_pending_entry() {
    let mut st = StateStore::new();

    let first_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("first unchecked pause write must succeed");
    assert!(st.is_emergency_paused());

    // Corrupt/legacy state simulation: stale pending residue must be scrubbed even
    // when the unchecked write is a noop.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_999,
        },
    );

    let second_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked noop pause write must stay idempotent");

    assert_eq!(
        first_ref, second_ref,
        "unchecked noop emergency_pause write must not churn version"
    );
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked noop must still remove stale emergency_pause pending entry"
    );
}

#[test]
fn emergency_pause_replace_action_scrubs_stale_pending_entry() {
    // Merge-gate guard: Replace action must stay on the immediate non-sensitive path,
    // including cleanup of any legacy/corrupt queued emergency_pause timelock entry.
    let mut st = StateStore::new();
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param_with_action(
            9_004,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace action should apply immediately for emergency_pause");

    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_still_enforces_strict_bool_schema() {
    // Merge-gate guard: action variants must not bypass strict bool validation.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            9_005,
            7_999,
            "emergency_pause".into(),
            "TRUE".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace action must reject non-strict bool literal");
    assert!(err.contains("expected strict bool"));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_action_scrubs_stale_pending_entry() {
    // Merge-gate guard: explicit Enforce must stay on the immediate non-sensitive path,
    // including cleanup of any legacy/corrupt queued emergency_pause timelock entry.
    let mut st = StateStore::new();
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 100_111,
        },
    );

    let applied = st
        .set_gov_param_with_action(
            9_006,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("enforce action should apply immediately for emergency_pause");

    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_action_invalid_literal_preserves_live_binding_and_pending_cleanliness() {
    // Merge-gate guard: Enforce must not bypass strict bool validation, and a rejected
    // payload must leave the live emergency brake and pending state untouched.
    let mut st = StateStore::new();
    st.set_gov_param(9_007, 7_999, "emergency_pause".into(), "true".into())
        .expect("baseline pause=true should apply immediately");
    let live_before = st.gov_param("emergency_pause").cloned();
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param_with_action(
            9_008,
            7_999,
            "emergency_pause".into(),
            "TRUE".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect_err("enforce action must reject non-strict bool literal");

    assert!(err.contains("expected strict bool"), "unexpected error: {err}");
    assert!(
        st.is_emergency_paused(),
        "rejected enforce payload must preserve the live emergency brake"
    );
    assert_eq!(
        st.gov_param("emergency_pause").cloned(),
        live_before,
        "rejected enforce payload must preserve the canonical live emergency_pause object"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "rejected enforce payload must not materialize pending emergency_pause state"
    );
}

#[test]
fn emergency_pause_toggles_preserve_challenge_escrow_conservation() {
    // Merge-gate guard: emergency pause is a control-plane brake only; it must never
    // mutate custody balances used by challenge escrow accounting.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 1_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 500);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_000, 7_999, "emergency_pause".into(), "true".into())
        .expect("checked pause write should apply immediately");
    st.set_gov_param(98_001, 7_999, "emergency_pause".into(), "false".into())
        .expect("checked unpause write should apply immediately");
    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked pause write should be accepted at canonical key id");

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
}
