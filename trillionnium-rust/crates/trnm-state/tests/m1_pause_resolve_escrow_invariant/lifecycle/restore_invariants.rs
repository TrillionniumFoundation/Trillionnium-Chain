use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_zero_task_version_boundary() {
    // M1 micro-hardening: paused rollback/restore must reject versionless pending resolve
    // snapshots so governance/resolve flow cannot revive an unversioned approval quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_020);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_002);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 502);

    st.set_gov_param(98_216, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_926, 0, true, "authority-a", "authority-a,authority-b")
        .expect_err("paused live resolve approval must reject zero task version");
    assert!(err.contains("task version"), "unexpected error: {err}");
    assert_eq!(st.pending_resolve_approval(9_926), None);
    assert_eq!(st.pending_resolve_first_approver(9_926), None);

    st.restore_pending_resolve_approval(
        9_927,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 0,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_927),
        None,
        "paused restore must scrub zero-version pending resolve snapshot"
    );
    assert_eq!(st.pending_resolve_first_approver(9_927), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_927), None);
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_reserved_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject case-variant reserved
    // custody/system aliases when they appear as the first approver itself, not only inside
    // the authority-set membership list.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_030);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_006);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 506);

    st.set_gov_param(98_219, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_930,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "Treasury.Challenge_Escrow".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_930),
        None,
        "paused restore must scrub reserved approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_930), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_930), None);
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_reserved_second_approver() {
    // M1 micro-hardening: paused rollback/restore must also reject malformed finalized
    // quorum snapshots when the second approver is a reserved custody/system alias under
    // case drift, so 2-of-N resolve history cannot be revived with a forbidden signer.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_932,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_932),
        None,
        "paused restore must scrub reserved second approver aliases under case drift"
    );
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

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_case_variant_duplicate_second_approver_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must reject finalized quorum snapshots when
    // the second approver is only a case-variant replay of the first approver, so restore
    // cannot resurrect a nominal 2-of-N resolve history that actually collapses to one actor.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_140);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_157);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 657);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_936,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(9_936),
        None,
        "paused restore must scrub duplicate second approver aliases under case drift"
    );
    assert_eq!(st.pending_resolve_first_approver(9_936), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_936), None);
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_delimiter_or_non_ascii_second_approver_boundary(
) {
    // M1 micro-hardening: paused rollback/restore must scrub finalized quorum snapshots when
    // the second approver uses delimiter smuggling or non-ASCII spellings, so malformed 2-of-N
    // resolve history cannot be revived through restore.
    for (task_id, _malformed_second_approver) in [
        (9_936, "authority|b"),
        (9_937, "authority；b"),
        (9_938, "authority，b"),
        (9_939, "authorité-b"),
    ] {
        let mut st = StateStore::new();
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_208);
        st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 708);

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
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: 1,
            }),
        );

        assert_eq!(
            st.pending_resolve_approval(task_id),
            None,
            "paused restore must scrub malformed finalized second approver ids"
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

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_second_approver_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub finalized quorum snapshots when
    // the second approver breaches the canonical actor-id length boundary, so malformed 2-of-N
    // approvals cannot be revived into paused resolve history.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_141);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_208);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 708);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let _oversized_second_approver = "b".repeat(129);
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
        "paused restore must scrub oversized finalized second approver ids"
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
fn paused_state_restore_pending_resolve_snapshot_scrubs_zero_task_id_boundary() {
    // M1 micro-hardening: paused rollback/restore must also fail closed on task-id zero so
    // malformed snapshots cannot revive pending resolve quorum outside a real challenged task.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_043);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 510);

    st.set_gov_param(98_223, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    st.restore_pending_resolve_approval(
        0,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(0), None);
    assert_eq!(st.pending_resolve_first_approver(0), None);
    assert_eq!(st.pending_resolve_approval_snapshot(0), None);
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
    assert_eq!(
        st.state_root(),
        root_before,
        "scrubbing zero-task restore input must not perturb paused custody or quorum state"
    );
}

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_oversized_approver_boundary() {
    // M1 micro-hardening: paused rollback/restore must scrub oversized approver ids so
    // malformed quorum snapshots cannot bypass live approver-size validation.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_042);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    st.set_gov_param(98_222, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_approver = "a".repeat(129);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.restore_pending_resolve_approval(
        9_933,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: oversized_approver,
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_933), None);
    assert_eq!(st.pending_resolve_first_approver(9_933), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_933), None);
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
