use super::*;

#[test]
fn paused_node_gate_skips_version_drift_resolve_replay_without_clearing_staged_quorum() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_500,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_2);

    let first = apply_one(
        &mut st,
        MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-a".into(),
        },
        130,
    );
    assert!(matches!(
        first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
        Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
    ));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let mut task_before = st.get_task(r5.id).expect("challenged task must exist");
    task_before.version += 1;
    st.restore_task(r5.id, Some(task_before.clone()));

    let paused_tx = MockTx::Resolve {
        task_id: r5.id,
        slash_worker: true,
        resolver: "authority-b".into(),
    };
    assert!(is_rejected_by_emergency_pause(true, &paused_tx));

    let pending_before = st.pending_resolve_approval_snapshot(r5.id);
    let escrow_before = st.balance_of("treasury.challenge_escrow");
    let forfeit_before = st.balance_of("treasury.challenge_forfeits");

    if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
        let _ = apply_one(&mut st, paused_tx, 131);
    }

    assert_eq!(
        st.pending_resolve_approval_snapshot(r5.id),
        pending_before,
        "pause gate must preserve staged multisig quorum across version-drift replay"
    );
    assert_eq!(
        st.get_task(r5.id).expect("task should remain challenged"),
        task_before
    );
    assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
}
