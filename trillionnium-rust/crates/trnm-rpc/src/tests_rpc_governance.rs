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
fn governance_state_merge_gate_emergency_pause_remains_immediate() {
    let mut st = governance_state();

    let pause = st
        .set_gov_param(
            9_001,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
        )
        .expect("pause update must succeed");
    assert!(matches!(
        pause,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(
        st.is_emergency_paused(),
        "pause=true must apply immediately"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "pause=true must not enqueue timelock state"
    );
    let paused_param = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("paused emergency_pause param must remain readable");
    assert_eq!(paused_param.value, "true");
    assert_eq!(
        paused_param.version, 2,
        "pause=true immediate apply must bump emergency_pause version"
    );

    let unpause = st
        .set_gov_param(
            9_002,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "false".into(),
        )
        .expect("unpause update must succeed");
    assert!(matches!(
        unpause,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(
        !st.is_emergency_paused(),
        "pause=false must apply immediately"
    );
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "pause=false must not enqueue timelock state"
    );
    let unpaused_param = st
        .get_param(EMERGENCY_PAUSE_KEY_ID)
        .expect("unpaused emergency_pause param must remain readable");
    assert_eq!(unpaused_param.value, "false");
    assert_eq!(
        unpaused_param.version, 3,
        "pause=false immediate apply must bump emergency_pause version"
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

#[test]
fn governance_state_merge_gate_emergency_pause_replace_action_stays_immediate() {
    let mut st = governance_state();

    let paused = st
        .set_gov_param_with_action(
            9_004,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
            trnm_state::GovPendingUpdateAction::Replace,
        )
        .expect("pause replace action must still succeed for non-sensitive key");
    assert!(matches!(
        paused,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "replace action must not queue emergency_pause timelock"
    );

    let unpaused = st
        .set_gov_param_with_action(
            9_005,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "false".into(),
            trnm_state::GovPendingUpdateAction::Replace,
        )
        .expect("unpause replace action must still succeed for non-sensitive key");
    assert!(matches!(
        unpaused,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn governance_state_merge_gate_emergency_pause_enforce_action_stays_immediate() {
    let mut st = governance_state();

    let paused = st
        .set_gov_param_with_action(
            9_006,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "true".into(),
            trnm_state::GovPendingUpdateAction::Enforce,
        )
        .expect("pause enforce action must still succeed for non-sensitive key");
    assert!(matches!(
        paused,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "enforce action must not queue emergency_pause timelock"
    );

    let unpaused = st
        .set_gov_param_with_action(
            9_007,
            EMERGENCY_PAUSE_KEY_ID,
            "emergency_pause".into(),
            "false".into(),
            trnm_state::GovPendingUpdateAction::Enforce,
        )
        .expect("unpause enforce action must still succeed for non-sensitive key");
    assert!(matches!(
        unpaused,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

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
