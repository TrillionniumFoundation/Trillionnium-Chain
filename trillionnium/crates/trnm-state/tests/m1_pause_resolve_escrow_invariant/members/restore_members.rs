use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_placeholder_member() {
    // M1 micro-hardening: rollback/restore must scrub malformed pending resolve snapshots even
    // while paused, so control-plane placeholder aliases cannot be revived into paused quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_010);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_001);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 501);

    st.set_gov_param(98_215, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_925,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,Governance.Emergency_Pause".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_925),
        None,
        "paused restore must scrub placeholder-tainted pending resolve snapshot"
    );
    assert_eq!(st.pending_resolve_first_approver(9_925), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_925), None);
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_authority_member_boundary() {
    // M1 micro-hardening: paused rollback/restore must reject oversized authority-set members
    // just like live resolve approval staging, so malformed quorum members cannot bypass the
    // per-member actor-length boundary through snapshot restore.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_member = "a".repeat(129);
    let authority_set = format!("authority-a,{}", oversized_member);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_932,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set,
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_932), None);
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
