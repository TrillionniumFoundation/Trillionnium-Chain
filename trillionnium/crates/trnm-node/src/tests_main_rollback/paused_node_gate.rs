use super::*;

#[test]
fn paused_node_gate_skips_second_multisig_resolve_without_mutating_staged_or_escrow_state() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_500,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let (r5, _, _) = challenged_task_fixture(&mut st, 8109);

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

    st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let paused_tx = MockTx::Resolve {
        task_id: r5.id,
        slash_worker: true,
        resolver: "authority-b".into(),
    };
    assert!(is_rejected_by_emergency_pause(true, &paused_tx));

    let task_before = st.get_task(r5.id).expect("challenged task must exist");
    let pending_before = st.pending_resolve_approval(r5.id);
    let first_approver_before = st.pending_resolve_first_approver(r5.id);
    let escrow_before = st.balance_of("treasury.challenge_escrow");
    let forfeit_before = st.balance_of("treasury.challenge_forfeits");

    if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
        let _ = apply_one(&mut st, paused_tx, 131);
    }

    assert_eq!(
        st.pending_resolve_approval(r5.id),
        pending_before,
        "pause gate must preserve previously staged multisig approval"
    );
    assert_eq!(
        st.pending_resolve_first_approver(r5.id),
        first_approver_before,
        "pause gate must preserve staged first approver identity"
    );
    assert_eq!(
        st.get_task(r5.id).expect("task should remain challenged"),
        task_before
    );
    assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
}

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

#[test]
fn paused_node_gate_skips_first_multisig_resolve_without_staging_or_escrow_drift() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_500,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_1);

    st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let paused_tx = MockTx::Resolve {
        task_id: r5.id,
        slash_worker: true,
        resolver: "authority-a".into(),
    };
    assert!(is_rejected_by_emergency_pause(true, &paused_tx));

    let task_before = st.get_task(r5.id).expect("challenged task must exist");
    let pending_before = st.pending_resolve_approval(r5.id);
    let first_approver_before = st.pending_resolve_first_approver(r5.id);
    let escrow_before = st.balance_of("treasury.challenge_escrow");
    let forfeit_before = st.balance_of("treasury.challenge_forfeits");

    if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
        let _ = apply_one(&mut st, paused_tx, 131);
    }

    assert_eq!(
        st.pending_resolve_approval(r5.id),
        pending_before,
        "pause gate must block first multisig approval staging"
    );
    assert_eq!(
        st.pending_resolve_first_approver(r5.id),
        first_approver_before,
        "pause gate must not synthesize staged first approver state"
    );
    assert_eq!(
        st.get_task(r5.id).expect("task should remain challenged"),
        task_before
    );
    assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
}

#[test]
fn paused_node_gate_skips_pending_replacement_resolve_without_mutating_timelock_or_escrow_state() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_3);

    let scheduled = st
        .set_gov_param(
            9_998,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority should schedule before pause");
    assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));
    let pending_gov_before = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");

    st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let paused_tx = MockTx::Resolve {
        task_id: r5.id,
        slash_worker: true,
        resolver: "authority-a".into(),
    };
    assert!(is_rejected_by_emergency_pause(true, &paused_tx));

    let task_before = st.get_task(r5.id).expect("challenged task must exist");
    let pending_quorum_before = st.pending_resolve_approval_snapshot(r5.id);
    let escrow_before = st.balance_of("treasury.challenge_escrow");
    let forfeit_before = st.balance_of("treasury.challenge_forfeits");

    if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
        let _ = apply_one(&mut st, paused_tx, 131);
    }

    assert_eq!(
        st.pending_resolve_approval_snapshot(r5.id),
        pending_quorum_before,
        "pause gate must not synthesize or clear staged quorum while a replacement authority is pending"
    );
    assert_eq!(
        st.pending_gov_update("resolve_authority"),
        Some(pending_gov_before),
        "pause gate must not mutate pending resolve_authority timelock state"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b"),
        "pending replacement authority must not apply early while paused"
    );
    assert_eq!(
        st.get_task(r5.id).expect("task should remain challenged"),
        task_before
    );
    assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
}
