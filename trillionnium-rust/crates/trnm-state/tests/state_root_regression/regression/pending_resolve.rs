use super::*;

#[test]
fn pending_resolve_finalized_restore_without_second_approver_scrubs_and_rewinds() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_eq!(state_b.pending_resolve_approval(5_150), None);
    assert_ne!(
        root_a, root_b,
        "finalized restore snapshots without an encoded second approver must scrub instead of materializing a fake quorum"
    );

    state_b.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original staged snapshot should rewind the deterministic root exactly"
    );
}
#[test]
fn restore_pending_resolve_snapshot_with_same_counts_but_different_authority_metadata_rewinds_state_root(
) {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5150, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5150);
    assert!(
        baseline_snapshot.is_some(),
        "sanity: snapshot should capture staged approval"
    );

    state.restore_pending_resolve_approval(
        5150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-b".into(),
            authority_set: "resolver-a,resolver-c".into(),
            task_version: 7,
        }),
    );

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "changing only pending resolve authority metadata must perturb state_root"
    );

    state.restore_pending_resolve_approval(5150, baseline_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the original pending resolve snapshot must rewind state_root exactly even when only authority metadata changed"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restoring pending resolve authority metadata should deterministically reuse the rewound cached root"
    );
}
#[test]
fn insertion_order_of_multiple_pending_resolve_entries_keeps_state_root_deterministic() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let first = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };
    let second = PendingResolveApprovalSnapshot {
        slash_worker: false,
        confirmations: 1,
        first_approver: "resolver-c".into(),
        authority_set: "resolver-c,resolver-d".into(),
        task_version: 11,
    };

    state_a.restore_pending_resolve_approval(5_160, Some(first.clone()));
    state_a.restore_pending_resolve_approval(5_161, Some(second.clone()));

    state_b.restore_pending_resolve_approval(5_161, Some(second));
    state_b.restore_pending_resolve_approval(5_160, Some(first));

    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should be deterministic for equivalent pending resolve snapshots regardless of insertion order"
    );
}
#[test]
fn restore_pending_resolve_snapshot_with_same_authority_metadata_but_different_task_version_rewinds_state_root(
) {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5_151, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5_151);
    assert!(
        baseline_snapshot.is_some(),
        "sanity: snapshot should capture staged approval"
    );

    state.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 8,
        }),
    );

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "changing only pending resolve task_version must perturb state_root"
    );

    state.restore_pending_resolve_approval(5_151, baseline_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the original pending resolve snapshot must rewind state_root exactly even when only task_version changed"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restoring pending resolve task_version should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_pending_resolve_none_on_mismatched_slot_keeps_canonical_pending_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(5_200, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let snapshot = state
        .pending_resolve_approval_snapshot(5_200)
        .expect("sanity: canonical pending resolve snapshot should exist");
    let canonical_pending_root = state.state_root();
    assert_ne!(
        canonical_pending_root, baseline_root,
        "sanity: staged pending resolve approval must perturb the root"
    );

    state.restore_pending_resolve_approval(5_201, Some(snapshot.clone()));
    assert!(
        state.pending_resolve_approval_snapshot(5_201).is_some(),
        "restoring a pending resolve snapshot through another task slot should materialize a distinct staged entry for that slot"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_200).is_some(),
        "mismatched-slot restore must preserve the canonical pending task slot"
    );
    assert_ne!(
        state.state_root(),
        canonical_pending_root,
        "adding the same pending resolve snapshot under a second task slot must perturb the root because the task_id slot is part of state identity"
    );

    state.restore_pending_resolve_approval(5_201, None);
    assert!(
        state.pending_resolve_approval_snapshot(5_200).is_some(),
        "clearing a mismatched pending resolve slot with None must not delete the canonical staged task slot"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "clearing the extra mismatched pending resolve slot must return to the canonical pending root"
    );

    state.restore_pending_resolve_approval(5_200, None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the canonical pending resolve slot must return the state root to baseline"
    );
}
#[test]
fn restore_pending_resolve_none_is_slot_scoped_even_with_multiple_pending_entries() {
    let mut state = StateStore::new();

    state.restore_pending_resolve_approval(
        5_210,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state.restore_pending_resolve_approval(
        5_211,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-c".into(),
            authority_set: "resolver-c,resolver-d".into(),
            task_version: 9,
        }),
    );

    let root_with_both = state.state_root();
    assert!(state.pending_resolve_approval_snapshot(5_210).is_some());
    assert!(state.pending_resolve_approval_snapshot(5_211).is_some());

    state.restore_pending_resolve_approval(5_210, None);

    assert!(
        state.pending_resolve_approval_snapshot(5_210).is_none(),
        "slot-scoped restore should remove the targeted pending resolve entry"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_211).is_some(),
        "slot-scoped restore must preserve unrelated pending resolve entries"
    );
    assert_ne!(
        state.state_root(),
        root_with_both,
        "removing only one pending resolve entry should perturb the root while preserving unrelated pending resolve state"
    );

    let mut expected = StateStore::new();
    expected.restore_pending_resolve_approval(
        5_211,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-c".into(),
            authority_set: "resolver-c,resolver-d".into(),
            task_version: 9,
        }),
    );

    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "restore_pending_resolve_approval(None) should produce the same deterministic root as a canonical state containing only the preserved pending resolve entry"
    );

    state.restore_pending_resolve_approval(
        5_210,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    assert_eq!(
        state.state_root(),
        root_with_both,
        "restoring the removed pending resolve snapshot must rewind state_root exactly to the prior two-entry root"
    );
}
#[test]
fn restore_pending_none_rewinds_state_root_after_removing_staged_resolve_approval() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(88, 4, true, "resolver-a", "resolver-a,resolver-b")
        .expect("staging resolve approval should succeed");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged resolve approval must perturb the state root"
    );

    state.restore_pending_resolve_approval(88, None);

    assert!(
        state.pending_resolve_approval(88).is_none(),
        "restoring a missing pending snapshot should remove the staged resolve approval"
    );
    assert_eq!(
        state.pending_resolve_first_approver(88),
        None,
        "restoring a missing pending snapshot should also clear cached approver metadata"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_pending_resolve_approval(None) must rewind state_root exactly after deleting a staged approval"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_pending_resolve_approval(None) should deterministically reuse the rewound cached root"
    );
}
