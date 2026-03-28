use super::*;

#[test]
fn paused_state_restore_pending_resolve_snapshot_scrubs_non_challenged_task_boundary() {
    // L03 boundary hardening: paused rollback/restore must not revive pending resolve quorum
    // onto a task that is no longer challenged, even if task version and authority set still
    // superficially match. Resolve approvals are only valid on the challenged-state boundary.
    let mut st = StateStore::new();

    st.set_gov_param(
        98_330,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(
        98_350,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve_authority should apply after timelock");
    st.set_gov_param(98_351, 7_999, "emergency_pause".into(), "true".into())
        .expect("emergency pause should enable successfully");
    assert!(st.is_emergency_paused());

    st.put_task_new(TaskObject {
        task_id: 9_937,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
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
        challenger: None,
        challenge_bond_forfeited: None,
        version: 7,
    })
    .expect("non-challenged task should exist before restore attempt");

    st.restore_pending_resolve_approval(
        9_937,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(st.pending_resolve_approval(9_937), None);
    assert_eq!(st.pending_resolve_first_approver(9_937), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_937), None);
    assert!(st.pending_gov_update("resolve_authority").is_none());
    assert!(st.is_emergency_paused());
}

#[test]
fn resolve_authority_same_value_replace_preserves_pending_timelock_and_staged_quorum() {
    // L03 boundary hardening: replaying an identical pre-activation resolve_authority replacement
    // must be idempotent. It must not extend the timelock or scrub already staged quorum because
    // the governance boundary itself did not change.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_325,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_345,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let first_replace = st
        .set_gov_param_with_action(
            98_346,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should schedule");
    let activate_at_height = match first_replace {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    let first = st
        .stage_or_confirm_resolve_approval(9_982, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before idempotent replay");
    assert!(!first);
    let pending_before = st
        .pending_resolve_approval_snapshot(9_982)
        .expect("staged quorum should exist before replaying identical replace");
    let root_with_pending = st.state_root();

    let replayed = st
        .set_gov_param_with_action(
            98_347,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("identical replacement replay should be idempotent");
    assert_eq!(
        replayed,
        GovParamUpdateOutcome::Scheduled { activate_at_height }
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_982),
        Some(pending_before),
        "identical replace replay must preserve staged quorum"
    );
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "idempotent replace replay must not perturb state root"
    );
}

#[test]
fn paused_resolve_authority_activation_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: once a timelocked resolve_authority update activates under
    // emergency_pause, any quorum staged against the pending authority set must be scrubbed so
    // stale paused-state approvals cannot survive the authority boundary crossing.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_328,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_348,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_349,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    let activate_at_height = match replacement {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    st.set_gov_param(98_350, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_983, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before activation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_983), Some((true, 1)));
    let root_with_pending = st.state_root();

    let activated = st
        .set_gov_param(
            activate_at_height,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("timelocked resolve_authority should still apply while paused");
    assert!(matches!(activated, GovParamUpdateOutcome::Applied(_)));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-c,authority-d")
    );
    assert_eq!(st.pending_resolve_approval(9_983), None);
    assert_eq!(st.pending_resolve_first_approver(9_983), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_983), None);
    assert!(st.is_emergency_paused());
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "activating resolve_authority under pause must invalidate cached state root when scrubbing staged quorum"
    );
}

#[test]
fn resolve_authority_pending_cancel_scrubs_pending_resolve_approvals() {
    // L03 boundary hardening: cancelling a staged resolve_authority timelock is still a
    // governance boundary transition and must scrub any staged resolve quorum immediately.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_330,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_350,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_351,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    let first = st
        .stage_or_confirm_resolve_approval(9_981, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before cancellation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_981), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_352,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("pending resolve_authority update should cancel cleanly");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(9_981), None);
    assert_eq!(st.pending_resolve_first_approver(9_981), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_981), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "cancelling a pending resolve_authority boundary must invalidate cached state root"
    );
}

#[test]
fn restore_pending_resolve_authority_none_scrubs_pending_resolve_approvals() {
    // L03 restore-boundary hardening: replaying a `None` snapshot into the resolve_authority
    // pending slot is still an authority-boundary rollback and must scrub any staged resolve
    // quorum immediately instead of leaving approvals armed against the old pending keyset.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_360,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_380,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_381,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

    let first = st
        .stage_or_confirm_resolve_approval(9_984, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before restore removal");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_984), Some((true, 1)));
    let root_with_pending = st.state_root();

    st.restore_pending_gov_update("resolve_authority", None);

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(9_984), None);
    assert_eq!(st.pending_resolve_first_approver(9_984), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_984), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "restoring away a pending resolve_authority boundary must invalidate cached state root"
    );
}

#[test]
fn paused_resolve_authority_pending_cancel_scrubs_pending_resolve_approvals() {
    // L03 paused-boundary hardening: cancelling a staged resolve_authority timelock while
    // emergency_pause is active is still an authority-boundary transition and must scrub any
    // staged resolve quorum without unpausing or mutating the active authority set.
    let mut st = StateStore::new();

    let bootstrap = st
        .set_gov_param(
            98_360,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_380,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_381,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_382, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let first = st
        .stage_or_confirm_resolve_approval(9_985, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval before paused cancellation");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(9_985), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_383,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("pending resolve_authority update should cancel cleanly while paused");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(9_985), None);
    assert_eq!(st.pending_resolve_first_approver(9_985), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_985), None);
    assert!(st.is_emergency_paused());
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "paused cancellation of a pending resolve_authority boundary must invalidate cached state root"
    );
}
