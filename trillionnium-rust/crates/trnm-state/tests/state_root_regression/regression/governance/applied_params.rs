use super::*;

#[test]
fn restore_applied_gov_param_rewinds_state_root_after_value_mutation() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 111, "max_block_ms".into(), "500".into())
        .expect("initial governance param insertion should succeed");
    let baseline_snapshot = state
        .get_param(111)
        .expect("baseline governance param snapshot should exist");
    let root_before = state.state_root();

    state
        .set_gov_param(0, 111, "max_block_ms".into(), "650".into())
        .expect("governance param update should succeed");
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate applied governance param values so distinct active config cannot hash identically"
    );

    state.restore_gov_param(111, Some(baseline_snapshot));
    assert_eq!(
        state.state_root(),
        root_before,
        "restore_gov_param must rewind state_root exactly after an applied governance value mutation"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after restore_gov_param should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_gov_param_none_rewinds_state_root_after_removing_applied_param_and_index() {
    let mut state = StateStore::new();

    let empty_root = state.state_root();
    state
        .set_gov_param(0, 112, "max_parallel_workers".into(), "8".into())
        .expect("governance param insertion should succeed");
    let applied_root = state.state_root();

    assert_ne!(
        applied_root, empty_root,
        "state_root should incorporate both the applied governance param object and its key index mapping"
    );

    state.restore_gov_param(112, None);

    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_gov_param(None) must rewind state_root exactly after deleting an applied governance param and its key index entry"
    );
    assert!(
        state.get_param(112).is_none(),
        "restore_gov_param(None) should remove the applied governance param object"
    );
    assert!(
        state.gov_param_string("max_parallel_workers").is_none(),
        "restore_gov_param(None) should also clear the gov_param_key_index mapping so readers cannot resolve a deleted key"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after restore_gov_param(None) should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_gov_param_none_is_slot_scoped_even_with_multiple_applied_entries() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state
        .set_gov_param(0, 7_101, "max_block_ms".to_string(), "500".to_string())
        .expect("first applied governance param should succeed");
    let only_max_block_ms_root = state.state_root();

    state
        .set_gov_param(
            0,
            7_102,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("second applied governance param should succeed");
    let root_with_both = state.state_root();

    assert_ne!(
        root_with_both, only_max_block_ms_root,
        "sanity: adding a second applied governance param must perturb state_root"
    );

    state.restore_gov_param(7_101, None);

    assert!(
        state.get_param(7_101).is_none(),
        "slot-scoped restore should remove the targeted applied governance param object"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms"),
        None,
        "slot-scoped restore should clear the targeted key-index mapping"
    );
    assert_eq!(
        state.gov_param_string("max_parallel_workers").as_deref(),
        Some("8"),
        "slot-scoped restore must preserve unrelated applied governance params"
    );
    assert_ne!(
        state.state_root(),
        empty_root,
        "removing one applied governance param must not collapse to the empty baseline while another applied entry still exists"
    );

    let mut expected = StateStore::new();
    expected
        .set_gov_param(
            0,
            7_102,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("canonical preserved applied governance param should succeed");
    let only_max_parallel_workers_root = expected.state_root();

    assert_eq!(
        state.state_root(),
        only_max_parallel_workers_root,
        "restore_gov_param(None) should produce the same deterministic root as a canonical state containing only the preserved applied governance param"
    );

    state.restore_gov_param(
        7_101,
        Some(GovParamObject {
            key_id: 7_101,
            key: "max_block_ms".to_string(),
            value: "500".to_string(),
            version: 1,
        }),
    );
    assert_eq!(
        state.state_root(),
        root_with_both,
        "restoring the removed applied governance snapshot must rewind state_root exactly to the prior two-entry root"
    );
}
#[test]
fn restore_gov_param_none_on_mismatched_slot_keeps_canonical_applied_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 7_181, "max_block_ms".to_string(), "500".to_string())
        .expect("canonical applied governance param should succeed");
    let canonical_snapshot = state
        .get_param(7_181)
        .expect("canonical applied governance param snapshot should exist");
    let canonical_root = state.state_root();

    state
        .set_gov_param(
            0,
            7_182,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("stale foreign applied governance param should succeed");
    let root_with_stale_foreign_slot = state.state_root();
    assert_ne!(
        root_with_stale_foreign_slot, canonical_root,
        "sanity: adding a foreign applied governance slot must perturb state_root"
    );

    state.restore_gov_param(7_182, None);

    assert!(
        state.get_param(7_182).is_none(),
        "clearing a mismatched applied governance slot with None should remove only the targeted foreign slot"
    );
    assert_eq!(
        state.get_param(7_181),
        Some(canonical_snapshot),
        "clearing a mismatched applied governance slot with None must preserve the canonical applied governance object"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "clearing a mismatched applied governance slot with None must preserve the canonical key-index mapping"
    );
    assert_eq!(
        state.gov_param_string("max_parallel_workers"),
        None,
        "clearing a mismatched applied governance slot with None must not delete the canonical key by alias"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "clearing a mismatched applied governance slot with None must preserve the canonical deterministic applied-param root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after clearing a mismatched applied governance slot with None should deterministically reuse the canonical cached root"
    );
}

#[test]
fn restore_gov_param_mismatched_slot_preserves_canonical_applied_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 7_201, "max_block_ms".to_string(), "500".to_string())
        .expect("canonical applied governance param should succeed");
    let canonical_snapshot = state
        .get_param(7_201)
        .expect("canonical applied governance param snapshot should exist");
    let canonical_root = state.state_root();

    state
        .set_gov_param(
            0,
            7_202,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("stale foreign applied governance param should succeed");
    let root_with_stale_foreign_slot = state.state_root();
    assert_ne!(
        root_with_stale_foreign_slot, canonical_root,
        "sanity: adding a foreign applied governance param slot must perturb state_root"
    );

    state.restore_gov_param(7_202, Some(canonical_snapshot.clone()));

    assert!(
        state.get_param(7_202).is_none(),
        "mismatched-slot restore should clear the targeted foreign applied governance slot"
    );
    assert_eq!(
        state.get_param(7_201),
        Some(canonical_snapshot.clone()),
        "mismatched-slot restore must preserve the canonical applied governance object"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "mismatched-slot restore must preserve the canonical key-index mapping"
    );
    assert_eq!(
        state.gov_param_string("max_parallel_workers"),
        None,
        "mismatched-slot restore must not alias the foreign slot into the canonical key index"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "mismatched-slot restore should fail closed back to the canonical deterministic applied-param root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after mismatched-slot restore should deterministically reuse the canonical cached root"
    );
}
#[test]
fn restore_gov_param_invalid_emergency_pause_literal_preserves_live_binding_and_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(98_246, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let canonical_snapshot = state
        .get_param(7_999)
        .expect("live canonical emergency_pause object must exist");
    let canonical_root = state.state_root();

    state.restore_gov_param(
        7_999,
        Some(GovParamObject {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: " TRUE ".into(),
            version: canonical_snapshot.version,
        }),
    );

    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".into()),
        "rejecting an invalid applied emergency_pause literal must preserve the live canonical pause binding"
    );
    assert!(
        state.is_emergency_paused(),
        "rejecting an invalid applied emergency_pause literal must preserve the active pause state"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "rejecting an invalid applied emergency_pause literal must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after rejecting an invalid applied emergency_pause literal should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_gov_param_noncanonical_emergency_pause_alias_preserves_live_binding_and_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(98_247, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let canonical_snapshot = state
        .get_param(7_999)
        .expect("live canonical emergency_pause object must exist");
    let canonical_root = state.state_root();

    state.restore_gov_param(
        7_999,
        Some(GovParamObject {
            key_id: 7_999,
            key: "emergency_pause ".into(),
            value: "false".into(),
            version: canonical_snapshot.version,
        }),
    );

    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".into()),
        "rejecting a non-canonical applied emergency_pause alias must preserve the live canonical pause binding"
    );
    assert!(
        state.gov_param_string("emergency_pause ").is_none(),
        "rejecting a non-canonical applied emergency_pause alias must not persist the malformed alias binding"
    );
    assert!(
        state.is_emergency_paused(),
        "rejecting a non-canonical applied emergency_pause alias must preserve the active pause state"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "rejecting a non-canonical applied emergency_pause alias must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after rejecting a non-canonical applied emergency_pause alias should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_gov_param_invalid_resolve_authority_literal_preserves_live_binding_and_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(
            98_247,
            7_998,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("canonical resolve_authority must be set first");
    let canonical_snapshot = state
        .get_param(7_998)
        .expect("live canonical resolve_authority object must exist");
    let canonical_root = state.state_root();

    state.restore_gov_param(
        7_998,
        Some(GovParamObject {
            key_id: 7_998,
            key: "resolve_authority".into(),
            value: "authority-a, authority-a".into(),
            version: canonical_snapshot.version,
        }),
    );

    assert_eq!(
        state.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rejecting an invalid applied resolve_authority literal must preserve the live canonical authority binding"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "rejecting an invalid applied resolve_authority literal must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after rejecting an invalid applied resolve_authority literal should deterministically reuse the preserved cached root"
    );
}

#[test]
fn restore_gov_param_noncanonical_resolve_authority_alias_preserves_live_binding_and_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(
            98_248,
            7_998,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("canonical resolve_authority must be set first");
    let canonical_snapshot = state
        .get_param(7_998)
        .expect("live canonical resolve_authority object must exist");
    let canonical_root = state.state_root();

    state.restore_gov_param(
        7_998,
        Some(GovParamObject {
            key_id: 7_998,
            key: "resolve_authority ".into(),
            value: "authority-c".into(),
            version: canonical_snapshot.version,
        }),
    );

    assert_eq!(
        state.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rejecting a non-canonical applied resolve_authority alias must preserve the live canonical authority binding"
    );
    assert!(
        state.gov_param_string("resolve_authority ").is_none(),
        "rejecting a non-canonical applied resolve_authority alias must not persist the malformed alias binding"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "rejecting a non-canonical applied resolve_authority alias must preserve the prior deterministic root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after rejecting a non-canonical applied resolve_authority alias should deterministically reuse the preserved cached root"
    );
}

#[test]
fn cloned_cached_state_restore_roundtrip_rewinds_applied_gov_param_root_without_aliasing_original_index(
) {
    let mut original = StateStore::new();
    original
        .set_gov_param(0, 7_901, "max_block_ms".into(), "500".into())
        .expect("baseline applied governance param should succeed");

    let baseline_root = original.state_root();
    let baseline_snapshot = original
        .get_param(7_901)
        .expect("baseline applied governance snapshot should exist");
    let mut cloned = original.clone();

    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "cloned state should preserve the canonical cached applied-governance root before mutation"
    );
    assert_eq!(
        cloned.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "cloned state should preserve the canonical key-index mapping before mutation"
    );

    cloned.restore_gov_param(
        7_901,
        Some(GovParamObject {
            key_id: 7_901,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: baseline_snapshot.version,
        }),
    );

    let mutated_clone_root = cloned.state_root();
    assert_ne!(
        mutated_clone_root, baseline_root,
        "changing an applied governance key through restore_gov_param must perturb the cloned root because both object payload and key index are state-root inputs"
    );
    assert_eq!(
        cloned.gov_param_string("max_block_ms"),
        None,
        "clone-local restore mutation should rewrite the clone key index away from the original key"
    );
    assert_eq!(
        cloned.gov_param_string("max_parallel_workers").as_deref(),
        Some("8"),
        "clone-local restore mutation should expose the replacement applied governance key only inside the clone"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "clone-local applied governance mutation must not alias back into the original cached root"
    );
    assert_eq!(
        original.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "clone-local applied governance mutation must not rewrite the original key-index mapping"
    );

    cloned.restore_gov_param(7_901, Some(baseline_snapshot.clone()));

    assert_eq!(
        cloned.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "restoring the original applied governance snapshot should restore the canonical key-index mapping in the clone"
    );
    assert_eq!(
        cloned.gov_param_string("max_parallel_workers"),
        None,
        "restoring the original applied governance snapshot should remove the clone-only replacement key"
    );
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "restoring the cloned applied governance snapshot must rewind state_root exactly to the original canonical baseline"
    );
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "repeated reads after clone-local applied governance restore should deterministically reuse the rewound cached root"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "the original state's cached root must remain canonical after the clone restores its applied governance snapshot"
    );
}
