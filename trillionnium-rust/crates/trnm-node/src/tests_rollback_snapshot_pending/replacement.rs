use super::helpers::assert_pending_snapshot;
use super::*;

#[test]
fn rollback_snapshot_restores_pending_resolve_state_against_pending_replacement_authority() {
    let mut st = StateStore::new();
    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let _ = challenged_task_fixture(&mut st, 8_109);
    let before_task = st.get_task(8_109).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");
    let expected = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "authority-c".into(),
        authority_set: "authority-c,authority-d".into(),
        task_version: before_task.version,
    };

    let snapshot = TxRollbackSnapshot {
        task_id: 8_109,
        task: Some(before_task.clone()),
        balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
        pending_resolve_approval: Some(expected.clone()),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_pending_snapshot(&st, 8_109, before_task, before_escrow, expected);
}
