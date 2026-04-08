use super::*;

#[test]
fn emergency_pause_unchecked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: even unchecked writes must keep emergency_pause pinned to 7999.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param_unchecked(8_000, "emergency_pause".into(), "true".into())
        .expect_err("unchecked non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: emergency_pause must remain pinned to canonical key id.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param(8_050, 8_000, "emergency_pause".into(), "true".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation() {
    // Merge-gate guard: key-id mismatch must fail before value schema parsing,
    // so malformed values cannot alter error semantics.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param(8_051, 8_000, "emergency_pause".into(), "TRUE".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected first");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(
        !err.contains("strict bool"),
        "key-id mismatch path must not leak value-schema errors: {err}"
    );
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_replace_rejects_non_canonical_key_id_without_side_effects() {
    // Merge-gate guard: Replace action must enforce the same canonical key-id pinning.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            8_051,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace with non-canonical emergency_pause key_id must be rejected");

    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_cancel_wrong_key_id_is_rejected_without_scrubbing_state() {
    let mut st = StateStore::new();

    // Merge-gate guard: key_id mismatch must fail before any state cleanup/mutation,
    // even when legacy/corrupt pending emergency_pause data exists.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("expected_id=7999"), "{cancel_err}");

    let pending = st
        .pending_gov_update("emergency_pause")
        .expect("mismatched key_id path must not mutate pending state");
    assert_eq!(pending.key_id, 7_999);
    assert_eq!(pending.activate_at_height, 77_777);
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param(9_100, 7999, "emergency_pause".into(), "true".into())
        .unwrap();

    let err = st
        .set_gov_param(9_101, 8000, "emergency_pause".into(), "false".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));

    // Confirm canonical key id still controls pause state.
    st.set_gov_param(9_102, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_enforce_wrong_key_id_is_rejected_without_scrubbing_state() {
    let mut st = StateStore::new();
    st.set_gov_param(9_110, 7_999, "emergency_pause".into(), "true".into())
        .expect("baseline canonical pause write should succeed");
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 91_111,
        },
    );

    let err = st
        .set_gov_param_with_action(
            9_111,
            8_000,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect_err("enforce with non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(
        !err.contains("strict bool"),
        "key-id mismatch must fail before value-schema validation: {err}"
    );
    assert!(
        st.is_emergency_paused(),
        "mismatched enforce path must preserve the live emergency brake"
    );
    let pending = st
        .pending_gov_update("emergency_pause")
        .expect("mismatched enforce path must not scrub legacy pending residue");
    assert_eq!(pending.key_id, 7_999);
    assert_eq!(pending.value, "false");
    assert_eq!(pending.activate_at_height, 91_111);
}

#[test]
fn emergency_pause_checked_path_rejects_non_canonical_key_before_key_id_policy() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param(9_112, 8_000, "Emergency_Pause".into(), "false".into())
        .expect_err("non-canonical emergency_pause key spelling must fail before key-id policy");

    assert!(err.contains("governance key not allowed"), "unexpected error: {err}");
    assert!(
        !err.contains("expected_id=7999"),
        "non-canonical key spelling must fail before key-id mismatch handling: {err}"
    );
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}
