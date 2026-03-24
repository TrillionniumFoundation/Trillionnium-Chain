use super::*;

#[test]
fn restore_pending_gov_update_key_mismatch_fails_closed_without_aliasing_foreign_slot() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_success_bounty".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "mismatched restore snapshots must clear the requested slot instead of staging a corrupt alias"
    );
    assert!(
        state.pending_gov_update("challenge_success_bounty").is_none(),
        "mismatched restore snapshots must not materialize a foreign pending governance entry under snapshot.key"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "mismatched restore snapshots must fail closed without perturbing the deterministic root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after a mismatched restore must deterministically reuse the unchanged cached root"
    );
}
#[test]
fn pending_gov_restore_key_mismatch_clears_only_targeted_stale_slot_and_preserves_other_entries() {
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_301,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: 7_302,
            key: "max_block_ms".to_string(),
            value: "500".to_string(),
            activate_at_height: 33,
        }),
    );

    let canonical_other_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("canonical pending governance entry should exist before mismatched restore");
    let root_with_both = state.state_root();

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: 7_302,
            key: "challenge_success_bounty".to_string(),
            value: "12".to_string(),
            activate_at_height: 44,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched restore should fail closed by clearing only the targeted stale caller slot"
    );
    assert!(
        state.pending_gov_update("challenge_success_bounty").is_none(),
        "mismatched restore must not materialize a foreign pending governance key from snapshot.key"
    );
    assert_eq!(
        state.pending_gov_update("challenge_min_bond"),
        Some(canonical_other_snapshot.clone()),
        "mismatched restore must preserve unrelated canonical pending governance entries"
    );

    let mut expected = StateStore::new();
    expected.restore_pending_gov_update("challenge_min_bond", Some(canonical_other_snapshot));

    assert_ne!(
        state.state_root(),
        root_with_both,
        "clearing only the targeted stale caller slot must perturb the prior two-entry root"
    );
    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "after a mismatched restore, the deterministic root should match the canonical state containing only the preserved unrelated pending entry"
    );
}
