use super::*;

#[test]
fn governance_sensitive_pending_cancel_before_activation_removes_pending() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7321, "challenge_min_bond".into(), "100".into())
        .unwrap();

    st.set_gov_param(21_000, 7321, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let cancelled = st
        .set_gov_param_with_action(
            21_005,
            7321,
            "challenge_min_bond".into(),
            "".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap();
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}
#[test]
fn governance_param_snapshot_resolves_canonical_registry_binding() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7999, "resolve_authority".into(), "alice,bob".into())
        .unwrap();

    let snapshot = st
        .gov_param_snapshot("resolve_authority")
        .expect("canonical governance key should resolve through registry-backed snapshot accessor");

    assert_eq!(snapshot.key_id, 7999);
    assert_eq!(snapshot.key, "resolve_authority");
    assert_eq!(snapshot.value, "alice,bob");
    assert_eq!(snapshot.version, 1);
}

#[test]
fn governance_sensitive_apply_without_pending_is_unchanged() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7322, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(22_000, 7322, "challenge_min_bond".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 22_020
        }
    ));
}
#[test]
fn governance_sensitive_rate_limit_still_enforced_after_replace() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7323, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    st.set_gov_param(23_000, 7323, "challenge_window_blocks".into(), "120".into())
        .unwrap();

    st.set_gov_param_with_action(
        23_005,
        7323,
        "challenge_window_blocks".into(),
        "119".into(),
        GovPendingUpdateAction::Replace,
    )
    .unwrap();

    let err = st
        .set_gov_param_with_action(
            23_006,
            7323,
            "challenge_window_blocks".into(),
            "130".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}
