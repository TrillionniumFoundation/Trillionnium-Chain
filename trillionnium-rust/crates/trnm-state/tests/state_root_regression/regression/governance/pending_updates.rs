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
