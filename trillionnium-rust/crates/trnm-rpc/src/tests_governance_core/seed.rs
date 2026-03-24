pub(crate) use super::*;

fn governance_state_merge_gate_keeps_emergency_pause_seeded_unpaused() {
    let st = governance_state();

    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("governance_state must seed emergency_pause at canonical key id");
    assert_eq!(
        pause.key_id, EMERGENCY_PAUSE_KEY_ID,
        "emergency_pause canonical key_id drifted"
    );
    assert_eq!(pause.key, "emergency_pause");
    assert_eq!(pause.value, "false");
    assert_eq!(pause.version, 1);
    assert!(
        !st.is_emergency_paused(),
        "bootstrap governance_state must start unpaused"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "bootstrap governance_state must not leave emergency_pause queued"
    );
}
