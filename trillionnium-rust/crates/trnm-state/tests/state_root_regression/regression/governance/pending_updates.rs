use super::*;

#[test]
fn restore_pending_gov_update_rewinds_state_root_after_value_mutation() {
    let mut state = StateStore::new();

    let baseline_snapshot = PendingGovParamUpdate {
        key_id: 114,
        key: "challenge_min_bond".into(),
        value: "120".into(),
        activate_at_height: 250,
    };
    state.restore_pending_gov_update("challenge_min_bond", Some(baseline_snapshot.clone()));
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 114,
            key: "challenge_min_bond".into(),
            value: "150".into(),
            activate_at_height: 275,
        }),
    );
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate pending governance queue payloads so changed staged values/timelocks cannot hash identically"
    );

    state.restore_pending_gov_update("challenge_min_bond", Some(baseline_snapshot));
    assert_eq!(
        state.state_root(),
        root_before,
        "restore_pending_gov_update must rewind state_root exactly after a pending governance payload mutation"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after restore_pending_gov_update should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_pending_gov_update_none_rewinds_state_root_after_removal() {
    let mut state = StateStore::new();

    let empty_root = state.state_root();
    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 115,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 300,
        }),
    );
    let queued_root = state.state_root();

    assert_ne!(
        queued_root, empty_root,
        "state_root should incorporate pending governance queue entries so staged updates cannot be omitted from root accounting"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_pending_gov_update(None) must rewind state_root exactly after deleting a pending governance queue entry"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restore_pending_gov_update(None) should remove the staged governance queue entry"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after restore_pending_gov_update(None) should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_pending_gov_update_mismatched_snapshot_key_rewinds_state_root_by_removing_target_entry()
{
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 116,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 320,
        }),
    );
    let queued_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 116,
            key: "max_block_ms".into(),
            value: "450".into(),
            activate_at_height: 321,
        }),
    );

    let empty_root = StateStore::new().state_root();
    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_pending_gov_update should fail closed by removing the requested queue entry when the supplied snapshot key mismatches the restore target"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "mismatched restore snapshot should clear the requested pending governance entry"
    );
    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched restore snapshot must not insert a different pending governance key"
    );
    assert_ne!(
        queued_root,
        state.state_root(),
        "state_root should account for fail-closed removal when a pending governance restore snapshot does not match the requested key"
    );
}
#[test]
fn restore_pending_gov_update_rejects_zero_key_id_fail_closed() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 0,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "zero-id pending governance restore snapshots must fail closed instead of materializing a queued update"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-id pending governance restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-id pending governance restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_pending_gov_update_rejects_zero_key_id_for_special_key_paths() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_pending_gov_update(
        "emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 0,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 1,
        }),
    );

    assert!(
        state.pending_gov_update("emergency_pause").is_none(),
        "zero-id pending governance snapshots must fail closed even on special-key restore paths"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-id special-key pending governance restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-id special-key restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_pending_gov_update_zero_activation_height_emergency_pause_snapshot_preserves_live_binding_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_239, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        "emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 0,
        }),
    );

    assert!(
        state.pending_gov_update("emergency_pause").is_none(),
        "zero-activation emergency_pause restore snapshots must fail closed instead of materializing a queued toggle"
    );
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "rejecting an incomplete pending emergency_pause snapshot must preserve the live canonical pause binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "rejecting an incomplete pending emergency_pause snapshot must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting an incomplete pending emergency_pause snapshot should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_pending_gov_update_nonzero_emergency_pause_snapshot_preserves_live_binding_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_240, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        "emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("emergency_pause").is_none(),
        "nonzero emergency_pause restore snapshots must fail closed instead of materializing a queued toggle"
    );
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "rejecting a pending emergency_pause restore snapshot must preserve the live canonical pause binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "rejecting a pending emergency_pause restore snapshot must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting a pending emergency_pause restore snapshot should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_pending_gov_update_noncanonical_emergency_pause_alias_preserves_live_binding_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_241, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        " emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 7_999,
            key: " emergency_pause".into(),
            value: "false".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("emergency_pause").is_none(),
        "non-canonical emergency_pause alias restore must not materialize a canonical queued toggle"
    );
    assert!(
        state.pending_gov_update(" emergency_pause").is_none(),
        "non-canonical emergency_pause alias restore must fail closed instead of persisting an alias entry"
    );
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "rejecting a non-canonical pending emergency_pause alias must preserve the live canonical pause binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "rejecting a non-canonical pending emergency_pause alias must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting a non-canonical emergency_pause alias should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_pending_gov_update_whitespace_bool_literal_emergency_pause_preserves_live_binding_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_242, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        "emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: " false ".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("emergency_pause").is_none(),
        "whitespace emergency_pause restore literals must fail closed instead of materializing a queued toggle"
    );
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "rejecting a whitespace pending emergency_pause literal must preserve the live canonical pause binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "rejecting a whitespace pending emergency_pause literal must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting a whitespace pending emergency_pause literal should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_pending_gov_update_zero_key_id_resolve_authority_scrubs_pending_resolve_and_rewinds_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(5_240, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged pending resolve approval must perturb the root before zero-id resolve_authority replay"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_240).is_some(),
        "sanity: pending resolve approval should exist before the fail-closed resolve_authority restore"
    );

    state.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 0,
            key: "resolve_authority".into(),
            value: "resolver-a,resolver-b".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("resolve_authority").is_none(),
        "zero-id resolve_authority restore snapshots must fail closed instead of materializing a queued governance update"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_240).is_none(),
        "rejecting a zero-id resolve_authority restore snapshot must scrub staged pending resolve metadata"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "rejecting a zero-id resolve_authority restore snapshot must rewind state_root to the pre-staged baseline"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after zero-id resolve_authority rejection should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_gov_update_none_rewinds_state_root_after_removing_timelocked_update() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    let outcome = state
        .set_gov_param(
            1_000,
            7_001,
            "challenge_min_bond".to_string(),
            "5000".to_string(),
        )
        .expect("staging a sensitive governance update should succeed");
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: a staged governance update must perturb the state root"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "sanity: the pending governance update should be visible before restore"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restoring a missing governance snapshot should remove the staged update"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_gov_param_update(None) must rewind state_root exactly after deleting a staged governance update"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_gov_param_update(None) should deterministically reuse the rewound cached root"
    );
}
