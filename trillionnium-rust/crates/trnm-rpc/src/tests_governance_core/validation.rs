pub(crate) use super::*;

#[test]
fn governance_state_merge_gate_emergency_pause_rejects_invalid_bool_without_side_effects() {
    let mut st = governance_state();

    let err = st
        .set_gov_param(
            9_008,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "TRUE".into(),
        )
        .expect_err("invalid bool literal must be rejected");
    assert!(
        err.contains("expected strict bool 'true' or 'false'"),
        "{err}"
    );

    assert!(
        !st.is_emergency_paused(),
        "invalid bool reject path must keep emergency_pause unpaused"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "invalid bool reject path must not create pending timelock state"
    );

    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.value, "false");
}

#[test]
fn governance_state_merge_gate_emergency_pause_replace_rejects_invalid_bool_without_side_effects() {
    let mut st = governance_state();

    let err = st
        .set_gov_param_with_action(
            9_009,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "TRUE".into(),
            trnm_state::GovPendingUpdateAction::Replace,
        )
        .expect_err("replace action must reject non-strict bool literals");
    assert!(
        err.contains("expected strict bool 'true' or 'false'"),
        "{err}"
    );

    assert!(
        !st.is_emergency_paused(),
        "replace invalid-bool reject path must keep emergency_pause unpaused"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "replace invalid-bool reject path must not create pending timelock state"
    );

    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.value, "false");
}

#[test]
fn governance_state_merge_gate_emergency_pause_rejects_whitespace_bool_without_side_effects() {
    let mut st = governance_state();

    let err = st
        .set_gov_param(
            9_011,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true ".into(),
        )
        .expect_err("bool literal with trailing whitespace must be rejected");
    assert!(
        err.contains("expected strict bool 'true' or 'false'"),
        "{err}"
    );

    assert!(
        !st.is_emergency_paused(),
        "whitespace bool reject path must keep emergency_pause unpaused"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "whitespace bool reject path must not create pending timelock state"
    );

    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.value, "false");
}

#[test]
fn governance_state_merge_gate_emergency_pause_cancel_skips_value_parse_but_stays_side_effect_free()
{
    let mut st = governance_state();
    st.set_gov_param(
        0,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "false".into(),
    )
    .expect("seed governance param before cancel check");

    let err = st
        .set_gov_param_with_action(
            9_010,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            trnm_state::GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel must remain unsupported for non-sensitive emergency_pause");
    assert!(
        err.contains("cancel not supported for non-sensitive key"),
        "{err}"
    );
    assert!(
        !err.contains("invalid governance value"),
        "cancel path must skip strict bool parsing"
    );

    assert!(
        !st.is_emergency_paused(),
        "cancel reject path with invalid value must keep emergency_pause unpaused"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "cancel reject path must not create pending timelock state"
    );

    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.value, "false");
}
