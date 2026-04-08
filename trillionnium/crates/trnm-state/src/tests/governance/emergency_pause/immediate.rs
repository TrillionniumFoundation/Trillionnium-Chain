use super::*;

#[test]
fn emergency_pause_requires_strict_bool_literal() {
    let mut st = StateStore::new();

    for bad in [
        "TRUE", "False", "1", "yes", " true", "false ", "	true", "
true", "false
",
    ] {
        let err = st
            .set_gov_param_unchecked(7999, "emergency_pause".into(), bad.into())
            .unwrap_err();
        assert!(err.contains("strict bool"));
    }

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_flag_works() {
    let mut st = StateStore::new();
    assert!(!st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_is_immediate_and_non_cancellable() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param(8_000, 7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let cancel_err = st
        .set_gov_param_with_action(
            8_001,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    // Failed cancel must be side-effect free on pause state and pending queues.
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let applied_unpause = st
        .set_gov_param(8_002, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(matches!(applied_unpause, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_noop_update_is_idempotent_after_pause() {
    // Merge-gate guard: repeated identical emergency_pause writes should be side-effect free.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(8_010, 7_999, "emergency_pause".into(), "true".into())
        .expect("initial pause=true write must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param(8_011, 7_999, "emergency_pause".into(), "true".into())
        .expect("noop pause=true write must succeed");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(first_ref, second_ref, "noop must not churn object version");
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_remains_immediate_without_pending_state() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_000,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    // Replace action must remain immediate and non-scheduling in both directions.
    let unapplied = st
        .set_gov_param_with_action(
            9_001,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: Replace noop must stay immediate and avoid object-version churn.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_006,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("initial replace pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_007,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "replace noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_action_remains_immediate_without_pending_state() {
    // Merge-gate guard: explicit Enforce action must stay on the immediate path for
    // emergency pause and never route through timelock scheduling.
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_010,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let unapplied = st
        .set_gov_param_with_action(
            9_011,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: explicit Enforce noop must keep immediate semantics and avoid
    // object-version churn for emergency_pause.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_011,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("initial enforce pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_012,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("enforce noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "enforce noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_invalid_literal_fails_closed_without_pending_side_effects() {
    // Merge-gate guard: malformed pause toggles must not silently flip the live guardrail
    // or leave behind a staged update under any checked-action path.
    let mut st = StateStore::new();

    st.set_gov_param_with_action(
        9_020,
        7_999,
        "emergency_pause".into(),
        "true".into(),
        GovPendingUpdateAction::Replace,
    )
    .expect("baseline pause=true should apply immediately");
    assert!(st.is_emergency_paused());
    assert_eq!(st.gov_param_string("emergency_pause"), Some("true".into()));

    let err = st
        .set_gov_param_with_action(
            9_021,
            7_999,
            "emergency_pause".into(),
            "TRUE".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect_err("invalid emergency_pause literal must fail closed");
    assert!(err.contains("strict bool"), "unexpected error: {err}");

    assert!(
        st.is_emergency_paused(),
        "failed malformed toggle must preserve the prior live pause state"
    );
    assert_eq!(
        st.gov_param_string("emergency_pause"),
        Some("true".into()),
        "failed malformed toggle must preserve the canonical stored value"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "failed malformed toggle must not leave behind a pending governance entry"
    );
}

#[test]
fn emergency_pause_unchecked_invalid_literal_preserves_live_binding_and_pending_cleanliness() {
    // Merge-gate guard: unchecked path still validates the literal before any mutation,
    // so malformed input must not unpause a live guardrail or materialize queued residue.
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("baseline unchecked pause=true should succeed");
    assert!(st.is_emergency_paused());
    assert_eq!(st.gov_param_string("emergency_pause"), Some("true".into()));

    let err = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "TRUE".into())
        .expect_err("unchecked invalid emergency_pause literal must fail closed");
    assert!(err.contains("strict bool"), "unexpected error: {err}");

    assert!(
        st.is_emergency_paused(),
        "failed unchecked malformed toggle must preserve the prior live pause state"
    );
    assert_eq!(
        st.gov_param_string("emergency_pause"),
        Some("true".into()),
        "failed unchecked malformed toggle must preserve the canonical stored value"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "failed unchecked malformed toggle must not materialize pending governance residue"
    );
}

#[test]
fn emergency_pause_rejects_non_canonical_key_spelling_without_mutating_live_binding() {
    // Merge-gate guard: the emergency brake must stay bound to one canonical governance key
    // spelling, even when callers present the reserved key id with alias/case/whitespace drift.
    let mut st = StateStore::new();

    st.set_gov_param(9_030, 7_999, "emergency_pause".into(), "true".into())
        .expect("baseline canonical pause=true should apply immediately");
    let live_before = st.gov_param("emergency_pause").cloned();
    assert!(st.is_emergency_paused());

    for bad_key in ["Emergency_Pause", " emergency_pause", "emergency_pause "] {
        let err = st
            .set_gov_param(9_031, 7_999, bad_key.into(), "false".into())
            .expect_err("non-canonical emergency_pause key spelling must fail closed");
        assert!(err.contains("governance key not allowed"), "unexpected error: {err}");
    }

    assert!(
        st.is_emergency_paused(),
        "non-canonical key spelling must not unpause the live emergency brake"
    );
    assert_eq!(
        st.gov_param("emergency_pause").cloned(),
        live_before,
        "non-canonical key spelling must preserve the canonical live emergency_pause object"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "non-canonical key spelling must not materialize pending governance residue"
    );
}

#[test]
fn emergency_pause_unchecked_rejects_non_canonical_key_spelling_without_mutating_live_binding() {
    // Merge-gate guard: even unchecked/bootstrap-adjacent callers must present the canonical
    // emergency_pause spelling; alias/case/whitespace drift must fail closed before mutation.
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("baseline unchecked canonical pause=true should succeed");
    let live_before = st.gov_param("emergency_pause").cloned();
    assert!(st.is_emergency_paused());

    for bad_key in ["Emergency_Pause", " emergency_pause", "emergency_pause "] {
        let err = st
            .set_gov_param_unchecked(7_999, bad_key.into(), "false".into())
            .expect_err("unchecked non-canonical emergency_pause key spelling must fail closed");
        assert!(err.contains("governance key not allowed"), "unexpected error: {err}");
    }

    assert!(
        st.is_emergency_paused(),
        "unchecked non-canonical key spelling must not unpause the live emergency brake"
    );
    assert_eq!(
        st.gov_param("emergency_pause").cloned(),
        live_before,
        "unchecked non-canonical key spelling must preserve the canonical live emergency_pause object"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked non-canonical key spelling must not materialize pending governance residue"
    );
}
