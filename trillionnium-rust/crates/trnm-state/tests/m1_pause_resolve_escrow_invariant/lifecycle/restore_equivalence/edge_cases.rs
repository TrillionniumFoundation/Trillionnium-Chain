use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_accepts_case_and_order_equivalent_pending_replacement_authority(
) {
    // L03 boundary hardening: once a replacement resolve_authority set is already timelocked,
    // paused rollback/restore must still accept snapshots that semantically match that pending
    // boundary under case/order drift instead of scrubbing a valid staged quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_025);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_007);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 507);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_task(
        9_931,
        Some(TaskObject {
            task_id: 9_931,
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
            version: 3,
        }),
    );

    st.restore_pending_resolve_approval(
        9_931,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "Authority-D".into(),
            authority_set: "Authority-D,Authority-C".into(),
            task_version: 3,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_931), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_931).as_deref(),
        Some("Authority-D"),
        "restore should preserve approver audit spelling while accepting equivalent pending replacement authority semantics"
    );
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_931)
            .expect("equivalent pending replacement snapshot should survive paused restore")
            .authority_set,
        "Authority-D,Authority-C"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured governance resolve_authority should remain unchanged until the replacement timelock matures"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
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
