use super::*;

#[test]
fn rollback_snapshot_restores_case_and_order_equivalent_pending_replacement_authority_while_paused() {
    let mut st = StateStore::new();
    let bootstrap = st
        .set_gov_param(
            98_283,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_303,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_304,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let _ = challenged_task_fixture(&mut st, 8_115);
    st.set_gov_param(98_305, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_115).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");
    let before_forfeits = st.balance_of("treasury.challenge_forfeits");
    let before_slashes = st.balance_of("treasury.worker_slashes");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_115,
        task: Some(before_task.clone()),
        balances: vec![
            ("treasury.challenge_escrow".into(), Some(before_escrow)),
            ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
            ("treasury.worker_slashes".into(), Some(before_slashes)),
        ],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "Authority-D".into(),
            authority_set: "Authority-D,Authority-C".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_115).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), before_forfeits);
    assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
    assert_eq!(st.pending_resolve_approval(8_115), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(8_115).as_deref(),
        Some("authority-d")
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(8_115),
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "authority-d".into(),
            authority_set: "authority-c,authority-d".into(),
            task_version: before_task.version,
        })
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rollback restore must preserve the active configured authority until the replacement matures"
    );
    assert!(st.is_emergency_paused());
}

#[test]
fn rollback_snapshot_scrubs_stale_configured_resolve_state_when_pending_replacement_exists() {
    let mut st = StateStore::new();
    let bootstrap = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_280,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_281,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let _ = challenged_task_fixture(&mut st, 8_114);

    st.set_gov_param(98_282, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_114).unwrap();
    let before_escrow = st.balance_of("treasury.challenge_escrow");
    let before_forfeits = st.balance_of("treasury.challenge_forfeits");
    let before_slashes = st.balance_of("treasury.worker_slashes");

    let snapshot = TxRollbackSnapshot {
        task_id: 8_114,
        task: Some(before_task.clone()),
        balances: vec![
            ("treasury.challenge_escrow".into(), Some(before_escrow)),
            ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
            ("treasury.worker_slashes".into(), Some(before_slashes)),
        ],
        pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: before_task.version,
        }),
    };

    rollback_tx_snapshot(&mut st, snapshot);

    assert_eq!(st.get_task(8_114).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), before_forfeits);
    assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
    assert_eq!(st.pending_resolve_approval(8_114), None);
    assert_eq!(st.pending_resolve_first_approver(8_114), None);
    assert_eq!(st.pending_resolve_approval_snapshot(8_114), None);
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rollback scrub must not mutate the active configured authority set"
    );
    assert!(st.is_emergency_paused());
}
