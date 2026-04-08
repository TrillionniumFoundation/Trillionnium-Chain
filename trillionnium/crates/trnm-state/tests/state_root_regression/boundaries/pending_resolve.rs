use super::*;

#[test]
fn pending_resolve_string_field_boundaries_should_affect_state_root() {
    let mut st_a = StateStore::new();
    let mut st_b = StateStore::new();

    st_a.stage_or_confirm_resolve_approval(9_101, 1, true, "ab", "ab,c")
        .expect("first pending resolve snapshot should be valid");
    st_b.stage_or_confirm_resolve_approval(9_101, 1, true, "a", "a,bc")
        .expect("second pending resolve snapshot should be valid");

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "state_root should length-frame pending resolve approver and authority-set strings so field-boundary collisions cannot hash identically"
    );
}
#[test]
fn pending_resolve_task_id_must_affect_state_root_even_when_snapshot_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "authority.alpha".into(),
        authority_set: "authority.alpha,authority.beta".into(),
        task_version: 3,
    };

    state_a.restore_pending_resolve_approval(4_201, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(4_202, Some(snapshot));

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "state_root must include the pending resolve task id so identical approval payloads staged for different tasks cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        4_202,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    state_b
        .restore_pending_resolve_approval(4_201, state_a.pending_resolve_approval_snapshot(4_201));
    state_b.restore_pending_resolve_approval(4_202, None);

    assert_eq!(
        state_b.state_root(),
        root_a,
        "moving an identical pending resolve snapshot onto the original task id and removing the extra entry should rewind the deterministic root exactly"
    );
}
#[test]
fn pending_resolve_task_version_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 8,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_version must contribute to state_root so identical approval metadata against different task revisions cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_151,
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
        "restoring the original pending resolve task_version should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_reserved_authority_alias_snapshot_fails_closed_to_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_pending_resolve_approval(
        5_152,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,governance.resolve_authority".into(),
            task_version: 7,
        }),
    );

    assert!(
        state.pending_resolve_approval_snapshot(5_152).is_none(),
        "reserved authority aliases must fail closed during pending resolve snapshot restore"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "invalid pending resolve authority aliases must not perturb the canonical empty state root"
    );
}

#[test]
fn pending_resolve_reserved_first_approver_alias_fails_closed_to_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_pending_resolve_approval(
        5_153,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "governance.resolve_authority".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    assert!(
        state.pending_resolve_approval_snapshot(5_153).is_none(),
        "reserved first approver aliases must fail closed during pending resolve snapshot restore"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "invalid pending resolve first approver aliases must not perturb the canonical empty state root"
    );
}
