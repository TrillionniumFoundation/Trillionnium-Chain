use super::*;

#[test]
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

#[test]
fn governance_state_merge_gate_rejects_non_canonical_emergency_pause_key_id() {
    let mut st = governance_state();

    let err = st
        .set_gov_param(9_003, 8_000, "emergency_pause".into(), "true".into())
        .expect_err("non-canonical emergency_pause key id must be rejected");
    assert!(err.contains("governance key id mismatch"));

    // Reject path must be side-effect free on pause state and pending queues.
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
    let pause = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("canonical emergency_pause param must remain readable");
    assert_eq!(pause.key_id, EMERGENCY_PAUSE_KEY_ID);
    assert_eq!(pause.version, 1);
    assert_eq!(pause.value, "false");
}
