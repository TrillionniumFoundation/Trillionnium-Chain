use super::*;

#[test]
fn policy_tick_triggers_on_interval_and_updates_monetary_state() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_001,
        "monetary_policy_tick_interval_blocks".into(),
        "3".into(),
    )
    .expect("set interval");
    st.set_gov_param_unchecked(
        9_002,
        "monetary_policy_tick_cooldown_blocks".into(),
        "3".into(),
    )
    .expect("set cooldown");
    st.set_gov_param_unchecked(9_003, "monetary_base_issuance_per_tick".into(), "15".into())
        .expect("set issuance");
    st.set_gov_param_unchecked(9_004, "monetary_base_burn_per_tick".into(), "4".into())
        .expect("set burn");

    assert!(st.policy_tick(2).is_none());
    let e1 = st.policy_tick(3).expect("tick at h=3");
    assert_eq!(e1.net_delta, 11);
    assert_eq!(e1.tick_count, 1);
    assert_eq!(e1.block_height, 3);
    assert_eq!(e1.cooldown_blocks, 3);
    assert_eq!(e1.interval_param_version, 1);
    assert_eq!(e1.cooldown_param_version, 1);
    assert!(
        st.policy_tick(3).is_none(),
        "same height must be idempotent"
    );

    let e2 = st.policy_tick(6).expect("tick at h=6");
    assert_eq!(e2.tick_count, 2);
    assert_eq!(e2.total_minted, 30);
    assert_eq!(e2.total_burned, 8);
    assert_eq!(e2.net_issuance, 22);
}

#[test]
fn governance_param_schema_rejects_invalid_monetary_policy_bounds() {
    let mut st = StateStore::new();
    let err_interval = st
        .set_gov_param_unchecked(
            9_010,
            "monetary_policy_tick_interval_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_interval.contains("out of range"));

    let err_cooldown = st
        .set_gov_param_unchecked(
            9_011,
            "monetary_policy_tick_cooldown_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_cooldown.contains("out of range"));

    let err_issuance = st
        .set_gov_param_unchecked(
            9_012,
            "monetary_base_issuance_per_tick".into(),
            "1000000000001".into(),
        )
        .unwrap_err();
    assert!(err_issuance.contains("out of range"));

    let err_burn = st
        .set_gov_param_unchecked(9_013, "monetary_base_burn_per_tick".into(), "-1".into())
        .unwrap_err();
    assert!(err_burn.contains("expected u64"));
}

#[test]
fn policy_tick_fail_closed_when_monetary_params_incomplete() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_020,
        "monetary_policy_tick_interval_blocks".into(),
        "2".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_021, "monetary_base_issuance_per_tick".into(), "1".into())
        .unwrap();
    st.set_gov_param_unchecked(9_022, "monetary_base_burn_per_tick".into(), "0".into())
        .unwrap();

    assert!(!st.should_trigger_policy_tick(2));
    assert!(st.policy_tick(2).is_none());
    assert_eq!(st.monetary_state().tick_count, 0);
}

#[test]
fn policy_tick_cooldown_throttles_repeated_schedule_points() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_030,
        "monetary_policy_tick_interval_blocks".into(),
        "3".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(
        9_031,
        "monetary_policy_tick_cooldown_blocks".into(),
        "5".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_032, "monetary_base_issuance_per_tick".into(), "9".into())
        .unwrap();
    st.set_gov_param_unchecked(9_033, "monetary_base_burn_per_tick".into(), "2".into())
        .unwrap();

    assert!(st.should_trigger_policy_tick(3));
    let e1 = st.policy_tick(3).expect("first tick");
    assert_eq!(e1.tick_count, 1);

    assert!(!st.should_trigger_policy_tick(6));
    assert!(st.policy_tick(6).is_none(), "cooldown should block h=6");

    assert!(st.should_trigger_policy_tick(9));
    let e2 = st.policy_tick(9).expect("second tick after cooldown");
    assert_eq!(e2.tick_count, 2);
    assert_eq!(e2.total_minted, 18);
    assert_eq!(e2.total_burned, 4);
    assert_eq!(e2.net_issuance, 14);
}
