use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_emergency_pause_placeholder_approver(
) {
    // M1 micro-hardening: paused rollback/restore must also reject control-plane
    // emergency_pause placeholder aliases when they appear as the first approver itself,
    // not only inside authority-set membership or second-approver slots.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_019);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_005);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 505);

    let bootstrap = st
        .set_gov_param(
            98_219,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_239,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_240, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_926,
        Some(TaskObject {
            task_id: 9_926,
            creator: "creator-paused".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker-paused".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: Some("challenger-paused".into()),
            challenge_bond_forfeited: None,
            version: 2,
        }),
    );

    st.restore_pending_resolve_approval(
        9_926,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Governance.Emergency_Pause".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 2,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_926),
        None,
        "paused restore must scrub emergency_pause placeholder approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_926), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_926), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into())
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_approver() {
    // M1 micro-hardening: paused rollback/restore must reject control-plane placeholder aliases
    // when they appear as the first approver itself, not only inside the authority-set list.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_040);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    st.set_gov_param(98_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Governance.Resolve_Authority".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_931),
        None,
        "paused restore must scrub placeholder approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_931), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_931), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is a mixed-case control-plane placeholder alias, so restore
    // cannot revive a forbidden signer into 2-of-N resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_108);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 608);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_934,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_934),
        None,
        "paused restore must scrub placeholder second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_934), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_934), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_exact_placeholder_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is the exact canonical resolve_authority placeholder, not only
    // a case-drifted alias.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_091);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_133);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 633);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_934,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_934),
        None,
        "paused restore must scrub exact placeholder second approver aliases"
    );
    assert_eq!(st.pending_resolve_first_approver(9_934), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_934), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_emergency_pause_placeholder_second_approver(
) {
    // M1 micro-hardening: paused rollback/restore must also reject finalized quorum snapshots
    // when the second approver is a mixed-case emergency_pause control-plane placeholder, so
    // restore cannot revive a forbidden signer into 2-of-N resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_158);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 658);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_935,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_935),
        None,
        "paused restore must scrub emergency_pause placeholder second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_935), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_935), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_exact_emergency_pause_placeholder_approver_slots(
) {
    // M1 micro-hardening: paused rollback/restore must also reject the exact canonical
    // emergency_pause control-plane placeholder when it appears in either approver slot,
    // not only case-drifted aliases.
    for (task_id, confirmations, first_approver, _second_approver) in [
        (9_935, 1, "governance.emergency_pause", None),
        (9_936, 2, "authority-a", Some("governance.emergency_pause")),
    ] {
        let mut st = StateStore::new();
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_142);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_159);
        st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 659);

        st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        st.restore_pending_resolve_approval(
            task_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations,
                first_approver: first_approver.into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 1,
            }),
        );

        assert_eq!(
            st.pending_resolve_approval(task_id),
            None,
            "paused restore must scrub exact emergency_pause placeholder approver slots"
        );
        assert_eq!(st.pending_resolve_first_approver(task_id), None);
        assert_eq!(st.pending_resolve_approval_snapshot(task_id), None);
        assert_eq!(st.pending_gov_update("resolve_authority"), None);
        assert!(st.is_emergency_paused());
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeits_before
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            worker_slash_before
        );
    }
}
