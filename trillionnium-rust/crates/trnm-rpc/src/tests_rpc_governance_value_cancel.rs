use super::*;

#[test]
fn governance_state_merge_gate_emergency_pause_cancel_skips_value_parse_but_stays_side_effect_free()
{
    let mut st = governance_state();

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
