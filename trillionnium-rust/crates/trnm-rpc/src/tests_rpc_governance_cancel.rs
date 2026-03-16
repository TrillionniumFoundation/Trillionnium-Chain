use super::*;

#[test]
fn governance_state_merge_gate_emergency_pause_cancel_rejected_without_side_effects() {
    let mut st = governance_state();

    st.set_gov_param(
        9_006,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "true".into(),
    )
    .expect("pause=true must apply immediately");
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let err = st
        .set_gov_param_with_action(
            9_007,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
            trnm_state::GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel must remain unsupported for non-sensitive emergency_pause");
    assert!(
        err.contains("cancel not supported for non-sensitive key"),
        "{err}"
    );

    assert!(
        st.is_emergency_paused(),
        "cancel reject path must not flip emergency_pause"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "cancel reject path must not create pending timelock state"
    );
}

#[test]
fn governance_state_merge_gate_emergency_pause_cancel_wrong_key_id_rejected_without_mutation() {
    let mut st = governance_state();

    st.set_gov_param(
        9_007,
        EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause".into(),
        "true".into(),
    )
    .expect("pause=true must apply immediately");
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let err = st
        .set_gov_param_with_action(
            9_008,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            trnm_state::GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel with non-canonical key id must be rejected");
    assert!(err.contains("governance key id mismatch"), "{err}");

    // Reject path must be side-effect free.
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.value, "true");
}
