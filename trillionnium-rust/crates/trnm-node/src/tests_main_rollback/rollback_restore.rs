use super::*;

#[test]
fn rollback_snapshot_restores_task_balances_and_pending_resolve_state() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_499,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let _ = challenged_task_fixture(&mut st, 8100);
    let current_task_version = st
        .get_task(8100)
        .expect("challenged task must exist before staging approval")
        .version;
    st.stage_or_confirm_resolve_approval(
        8100,
        current_task_version,
        true,
        "authority-a",
        "authority-a,authority-b",
    )
    .unwrap();
    let before_task = st.get_task(8100).unwrap();
    let before_worker = st.balance_of("worker8100");
    let before_challenger = st.balance_of("challenger");
    let before_escrow = st.balance_of("treasury.challenge_escrow");
    let before_pending = st.pending_resolve_approval_snapshot(8100);

    let snapshot = capture_rollback_snapshot(
        &st,
        &MockTx::Resolve {
            task_id: 8100,
            slash_worker: true,
            resolver: "authority-b".into(),
        },
    );

    st.set_balance("worker8100", 0);
    st.set_balance("challenger", 0);
    st.set_balance("treasury.challenge_escrow", 0);
    let mut mutated_task = before_task.clone();
    mutated_task.status = TaskStatus::Completed;
    mutated_task.version += 1;
    st.restore_task(8100, Some(mutated_task));
    st.clear_pending_resolve_approval(8100);

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8100).unwrap(), before_task);
    assert_eq!(st.balance_of("worker8100"), before_worker);
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(st.pending_resolve_approval_snapshot(8100), before_pending);
}
