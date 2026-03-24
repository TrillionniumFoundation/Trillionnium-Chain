use super::*;

#[test]
fn governance_timelock_classification_merge_gate_keeps_emergency_pause_immediate() {
    // Exhaustive merge-gate guard for timelock classification: sensitivity is now read from
    // the static governance schema so any changed key must update one explicit registry row.
    let allowed_keys: Vec<&str> = gov_allowed_keys().collect();
    let sensitive_keys: Vec<&str> = gov_sensitive_keys().collect();
    let expected_sensitive_count = GOV_PARAM_SCHEMA
        .iter()
        .filter(|entry| entry.is_sensitive())
        .count();
    assert_eq!(
        sensitive_keys.len(),
        expected_sensitive_count,
        "derived sensitive-key view changed; update timelock classification merge gate"
    );

    for entry in GOV_PARAM_SCHEMA {
        assert!(
            allowed_keys.contains(&entry.key),
            "timelock merge gate contains non-whitelisted key: {}",
            entry.key
        );
        assert_eq!(
            is_sensitive_gov_param(entry.key),
            entry.is_sensitive(),
            "governance sensitivity drifted for key: {}",
            entry.key
        );
    }

    // Behavioral merge-gate: pause must remain immediate (never timelocked/scheduled).
    let mut st = StateStore::new();
    let outcome = st
        .set_gov_param(96_100, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause update");
    assert!(
        matches!(outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause must apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(st.is_emergency_paused());

    let unpause_outcome = st
        .set_gov_param(96_101, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause update");
    assert!(
        matches!(unpause_outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause=false must also apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}
