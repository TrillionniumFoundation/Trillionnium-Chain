use super::*;

#[test]
fn pending_resolve_task_id_slot_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };

    state_a.restore_pending_resolve_approval(5_148, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(5_149, Some(snapshot.clone()));

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_id slot must contribute to state_root so identical approval payloads on different tasks cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(5_149, None);
    state_b.restore_pending_resolve_approval(5_148, Some(snapshot));

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending resolve task_id slot should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_slash_worker_flag_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve slash_worker must contribute to state_root so slash-vs-refund intent cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
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
        "restoring the original slash_worker flag should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_confirmations_count_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
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
    assert_ne!(
        root_a, root_b,
        "pending resolve confirmations count must contribute to state_root so one-of-two and finalized quorum snapshots cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
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
        "restoring the original pending resolve confirmations count should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_first_approver_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-b".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve first_approver must contribute to state_root so identical quorum state with different initial approvers cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
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
        "restoring the original pending resolve first_approver should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_authority_set_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-c".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve authority_set must contribute to state_root so different resolver quorums cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
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
        "restoring the original pending resolve authority_set should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_task_version_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
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
        "pending resolve task_version must contribute to state_root so approvals for different object versions cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
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
fn pending_resolve_task_slot_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };

    state_a.restore_pending_resolve_approval(5_300, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(5_301, Some(snapshot.clone()));

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_id slot must contribute to state_root so identical approval snapshots staged under different task slots cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(5_301, None);
    state_b.restore_pending_resolve_approval(5_300, Some(snapshot));
    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending resolve snapshot under the original task slot should rewind the deterministic root exactly"
    );
}
