use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_authority_set_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub oversized authority-set snapshots
    // so resolve quorum state cannot bypass the canonical governance length boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_022);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_004);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 504);

    st.set_gov_param(98_218, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let oversized_authority_set = format!("authority-a,{}", "b".repeat(117));
    assert!(oversized_authority_set.len() > 128);

    st.restore_pending_resolve_approval(
        9_929,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: oversized_authority_set,
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_929), None);
    assert_eq!(st.pending_resolve_first_approver(9_929), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_929), None);
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_authority_set_drift_from_configured_governance_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must not revive a pending resolve quorum whose
    // authority set no longer matches the configured resolve_authority governance boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_023);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_005);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 505);

    let bootstrap = st
        .set_gov_param(
            98_218,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_238,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    st.set_gov_param(98_239, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_929,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-c".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_929), None);
    assert_eq!(st.pending_resolve_first_approver(9_929), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_929), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "configured governance resolve_authority must remain unchanged"
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
