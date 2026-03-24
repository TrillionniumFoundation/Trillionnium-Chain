use super::*;

#[test]
fn restore_pending_gov_update_uses_snapshot_key_identity_for_state_root_roundtrip() {
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

    let baseline_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: pending snapshot should exist");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged governance update must perturb the root"
    );

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: baseline_snapshot.key_id,
            key: baseline_snapshot.key.clone(),
            value: baseline_snapshot.value.clone(),
            activate_at_height: baseline_snapshot.activate_at_height,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "restore should not materialize a pending update under a mismatched key slot"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "restore should preserve the original logical pending key"
    );
    assert_eq!(
        state.state_root(),
        pending_root,
        "restoring an identical pending snapshot through a mismatched caller key should preserve the same deterministic root"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "removing the pending update after the mismatched-key restore roundtrip must return to the original baseline root"
    );
}
#[test]
fn restore_pending_gov_update_none_on_mismatched_slot_keeps_canonical_pending_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    let outcome = state
        .set_gov_param(
            1_000,
            7_011,
            "challenge_min_bond".to_string(),
            "6100".to_string(),
        )
        .expect("sensitive governance update should stage successfully");
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    let snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: canonical pending snapshot should exist");
    let canonical_pending_root = state.state_root();
    assert_ne!(
        canonical_pending_root, baseline_root,
        "sanity: staged pending governance update must perturb the root"
    );

    state.restore_pending_gov_update("max_block_ms", Some(snapshot.clone()));
    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched-slot restore must not materialize a stale caller-key entry"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "mismatched-slot restore must preserve the canonical pending key"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "replaying the same snapshot through a mismatched slot must preserve the canonical pending root"
    );

    state.restore_pending_gov_update("max_block_ms", None);
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "clearing a mismatched slot with None must not delete the canonical pending key"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "clearing a mismatched slot with None must preserve the canonical pending root"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the canonical pending key must return the state root to baseline"
    );
}
#[test]
fn restore_pending_gov_update_none_is_slot_scoped_even_with_multiple_pending_entries() {
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_011,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state.restore_pending_gov_update(
        "challenge_success_bounty",
        Some(PendingGovParamUpdate {
            key_id: 7_012,
            key: "challenge_success_bounty".to_string(),
            value: "12".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_with_both = state.state_root();
    assert!(state.pending_gov_update("challenge_min_bond").is_some());
    assert!(state
        .pending_gov_update("challenge_success_bounty")
        .is_some());

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "slot-scoped restore should remove the targeted pending key"
    );
    assert!(
        state
            .pending_gov_update("challenge_success_bounty")
            .is_some(),
        "slot-scoped restore must preserve unrelated pending keys"
    );
    assert_ne!(
        state.state_root(),
        root_with_both,
        "removing only one pending key should perturb the root while preserving unrelated pending state"
    );
}
#[test]
fn restore_pending_gov_update_mismatched_slot_clears_stale_entry_and_preserves_snapshot_identity() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .set_gov_param(0, 111, "max_block_ms".to_string(), "500".to_string())
        .expect("non-sensitive baseline update should apply");
    let challenge_outcome = state
        .set_gov_param(
            1_000,
            7_002,
            "challenge_min_bond".to_string(),
            "6000".to_string(),
        )
        .expect("sensitive governance update should stage successfully");
    assert!(matches!(
        challenge_outcome,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    let challenge_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: pending challenge snapshot should exist");
    let challenge_root = state.state_root();
    assert_ne!(
        challenge_root, baseline_root,
        "sanity: pending challenge update must perturb the root"
    );

    state
        .set_gov_param(0, 111, "max_block_ms".to_string(), "650".to_string())
        .expect("updating a non-sensitive key should succeed");
    let root_before_restore = state.state_root();
    assert_ne!(
        root_before_restore, challenge_root,
        "sanity: mutating the mismatched caller slot should perturb the root before restore"
    );

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: challenge_snapshot.key_id,
            key: challenge_snapshot.key.clone(),
            value: challenge_snapshot.value.clone(),
            activate_at_height: challenge_snapshot.activate_at_height,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "restore through a mismatched slot must scrub any stale entry under the caller key"
    );
    let restored_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("challenge snapshot should remain addressable by its own key");
    assert_eq!(
        restored_snapshot.key, challenge_snapshot.key,
        "restore should preserve snapshot key identity"
    );
    assert_eq!(
        restored_snapshot.key_id, challenge_snapshot.key_id,
        "restore should preserve the staged governance key id"
    );
    assert_eq!(
        restored_snapshot.value, challenge_snapshot.value,
        "restore should preserve the staged governance value"
    );
    assert_eq!(
        restored_snapshot.activate_at_height, challenge_snapshot.activate_at_height,
        "restore should preserve the staged activation height"
    );
    assert_eq!(
        state.state_root(),
        root_before_restore,
        "re-inserting the identical logical snapshot while the caller slot is already non-pending should leave the deterministic root unchanged"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    state.restore_task(111, None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the preserved pending snapshot and reverting the helper mutation must return to the original baseline root"
    );
}
