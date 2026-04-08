use super::*;

#[test]
fn emergency_pause_does_not_mutate_pending_resolve_authority_update() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            13_000,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 13_020
        }
    ));

    st.set_gov_param(13_001, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    st.set_gov_param(13_002, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause toggle must apply immediately");

    assert!(!st.is_emergency_paused());
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should survive pause toggles");
    assert_eq!(pending.key_id, 7313);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 13_020);

    let applied = st
        .set_gov_param(
            13_020,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority should still activate at original timelock height");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn emergency_pause_does_not_mutate_other_sensitive_pending_updates() {
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(8_600, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 8_620);

    let pause_outcome = st
        .set_gov_param(8_601, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(pause_outcome, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("challenge_min_bond pending update must remain");
    assert_eq!(pending.key_id, 8_500);
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 8_620);
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_does_not_bypass_sensitive_timelock_guards() {
    // Merge-gate guard: paused mode must not allow sensitive governance params
    // to skip the timelock state machine.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(9_200, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };

    st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param(9_205, 8_500, "challenge_min_bond".into(), "120".into())
        .expect_err("paused mode must not bypass sensitive timelock");
    assert!(err.contains("timelock active"), "{err}");

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("timelock pending update must remain intact while paused");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(pending.value, "120");
}

#[test]
fn emergency_pause_does_not_let_replace_or_enforce_bypass_sensitive_timelock() {
    // Merge-gate guard: action-specific checked paths must keep sensitive params on the
    // same fail-closed timelock rails while emergency_pause is active.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(8_510, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(9_300, 8_510, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 9_320);

    st.set_gov_param(9_301, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let replace_err = st
        .set_gov_param_with_action(
            9_305,
            8_510,
            "challenge_min_bond".into(),
            "130".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("paused mode must not let Replace bypass a live sensitive timelock");
    assert!(replace_err.contains("timelock active"), "{replace_err}");

    let pending_after_replace = st
        .pending_gov_update("challenge_min_bond")
        .expect("replace rejection must preserve the staged sensitive update");
    assert_eq!(pending_after_replace.value, "120");
    assert_eq!(pending_after_replace.activate_at_height, activate_at_height);

    let enforce_err = st
        .set_gov_param_with_action(
            9_306,
            8_510,
            "challenge_min_bond".into(),
            "130".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect_err("paused mode must not let Enforce bypass a live sensitive timelock");
    assert!(enforce_err.contains("timelock active"), "{enforce_err}");

    let pending_after_enforce = st
        .pending_gov_update("challenge_min_bond")
        .expect("enforce rejection must preserve the staged sensitive update");
    assert_eq!(pending_after_enforce.value, "120");
    assert_eq!(pending_after_enforce.activate_at_height, activate_at_height);
}
