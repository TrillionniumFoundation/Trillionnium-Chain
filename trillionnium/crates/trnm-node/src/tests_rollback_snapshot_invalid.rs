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
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_authority_separator() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_502,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8_112);
    let before_task = st.get_task(8_112).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_112,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a；authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_112).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_112),
        None,
        "rollback must scrub authority snapshots with forbidden separators before replay"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_system_approver() {
    let mut st = StateStore::new();
    let _ = challenged_task_fixture(&mut st, 8_116);
    let before_task = st.get_task(8_116).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_116,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "system".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_116).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_116),
        None,
        "rollback must scrub reserved system approvers instead of reviving a forged quorum"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_whitespace_padded_authority_members() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_504,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8_114);
    let before_task = st.get_task(8_114).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_114,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a, authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_114).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_114),
        None,
        "rollback must scrub authority snapshots with whitespace-padded members before replay"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_emergency_pause_authority_member() {
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
            first_approver: "authority-a".into(),
            authority_set: "authority-a,governance.emergency_pause".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_115).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_115),
        None,
        "rollback must scrub authority snapshots that smuggle reserved governance.emergency_pause placeholder members"
    );
}

#[test]
fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_case_folded_duplicate_authorities() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_503,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8_113);
    let before_task = st.get_task(8_113).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_113,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "Authority-A,authority-a".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_113).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(
        st.pending_resolve_approval(8_113),
        None,
        "rollback must reject case-folded duplicate authority members during replay"
    );
}
