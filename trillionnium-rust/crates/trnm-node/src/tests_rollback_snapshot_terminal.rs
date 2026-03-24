use super::*;

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
fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_with_case_variant_duplicate_second_approver() {
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
