use super::*;

#[test]
fn rollback_snapshot_scrubs_invalid_pending_resolve_state() {
    let mut st = StateStore::new();
    let _ = challenged_task_fixture(&mut st, 8_110);
    let before_task = st.get_task(8_110).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_110,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 3,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_110).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_110),
        None,
        "rollback must not revive malformed pending resolve quorum state"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_state_when_task_version_drifts() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_501,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8_111);
    let before_task = st.get_task(8_111).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_111,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version + 1,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_111).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_111),
        None,
        "rollback must not revive staged resolve quorum for a stale task version"
    );
}

#[test]
fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_missing_second_approver() {
    let mut st = StateStore::new();
    let _ = challenged_task_fixture(&mut st, 8_112);
    let before_task = st.get_task(8_112).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_112,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_112).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_112),
        None,
        "rollback must not revive finalized resolve quorum without a distinct second approver audit trail"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_approver_separator() {
    let mut st = StateStore::new();
    let _ = challenged_task_fixture(&mut st, 8_111);
    let before_task = st.get_task(8_111).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_111,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority|a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_111).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_111),
        None,
        "rollback must scrub snapshot approvers that live parsing would reject"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_whitespace_padded_first_approver() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_505,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8_115);
    let before_task = st.get_task(8_115).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_115,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: " authority-a ".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_115).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_115),
        None,
        "rollback must scrub whitespace-padded approvers instead of silently normalizing them"
    );
    assert_eq!(st.pending_resolve_first_approver(8_115), None);
    assert_eq!(st.pending_resolve_approval_snapshot(8_115), None);
}

#[test]
fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_with_case_variant_duplicate_second_approver(
) {
    let mut st = StateStore::new();
    let _ = challenged_task_fixture(&mut st, 8_113);
    let before_task = st.get_task(8_113).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_113,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_113).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_113),
        None,
        "rollback must not revive finalized resolve quorum with a case-variant duplicate second approver"
    );
    assert_eq!(st.pending_resolve_first_approver(8_113), None);
    assert_eq!(st.pending_resolve_approval_snapshot(8_113), None);
}
