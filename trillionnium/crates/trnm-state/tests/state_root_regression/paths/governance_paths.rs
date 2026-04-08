use super::*;

#[test]
fn pending_sensitive_gov_updates_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let st2 = StateStore::new();

    // Base states are identical
    assert_eq!(st1.state_root(), st2.state_root());

    // Add a timelocked sensitive pending update to st1 only.
    let outcome = st1
        .set_gov_param(
            1000,
            7001,
            "challenge_min_bond".to_string(),
            "5000".to_string(),
        )
        .unwrap();
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    // Roots should now differ because pending_gov_updates contributes to state_root.
    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate pending sensitive governance updates"
    );
}

#[test]
fn embedded_pending_gov_update_key_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    st1.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );
    st2.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "min_worker_stake".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate embedded pending governance key names so mismatched restore snapshots cannot hash identically"
    );
}

#[test]
fn pending_gov_update_key_id_should_affect_state_root_even_when_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7002,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "pending governance key_id must contribute to state_root so identical staged payloads under different canonical key slots cannot hash identically"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance key_id should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_key_id_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance key_id must contribute to state_root so logically distinct staged updates do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance key_id should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_activation_height_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_021,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance activation height must contribute to state_root so distinct timelock schedules do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance activation height should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_value_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6500".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance value must contribute to state_root so distinct staged monetary/security settings do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance value should rewind the deterministic root exactly"
    );
}
