use super::*;

#[test]
fn legacy_revealed_without_snapshot_gets_snapshotted_on_challenge() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9130, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19130, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19130, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    // Simulate pre-snapshot legacy Revealed task persisted before rollout.
    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    st.set_gov_param_bootstrap_unchecked(9130, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        210,
    )
    .unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_window_blocks_snapshot, Some(300));
    assert_eq!(task.challenge_deadline_height, Some(210));
    assert_eq!(task.resolve_deadline_height, Some(510));
}

#[test]
fn legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19133, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19133, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    // Simulate pre-snapshot legacy Revealed task persisted before rollout.
    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        210,
    )
    .unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_window_blocks_snapshot, Some(300));
    assert_eq!(task.resolve_deadline_height, Some(510));

    // Later governance updates must not affect already-derived challenged timing.
    st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "600".into())
        .unwrap();

    let err = apply_timeout(&mut st, r5.clone(), 510).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));

    let r6 = apply_timeout(&mut st, r5, 511).unwrap();
    let timed_out = st.get_task(r6.id).unwrap();
    assert_eq!(timed_out.status, TaskStatus::Completed);
}

#[test]
fn legacy_revealed_without_snapshot_still_enforces_stored_challenge_deadline_under_gov_change() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9131, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19131, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19131, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    // Simulate pre-snapshot legacy Revealed task persisted before rollout.
    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    st.set_gov_param_bootstrap_unchecked(9131, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let err = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        211,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::DeadlineExceeded));
}

#[test]
fn revealed_timeout_auto_completes_without_challenge() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9103, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 903, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(903, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let before = apply_timeout(&mut st, r4.clone(), 210).unwrap_err();
    assert!(matches!(before, PouwError::InvalidTransition));

    let r5 = apply_timeout(&mut st, r4, 211).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenged_at_height, None);
    assert_eq!(task.challenge_deadline_height, None);
    assert_eq!(task.resolve_deadline_height, None);
}

#[test]
fn malformed_revealed_stale_challenge_fields_rejected_before_timeout_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39002, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39002, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut bad = st.get_task(r4.id).unwrap();
    bad.challenge_bond = Some(10);
    bad.challenger = Some("challenger".into());
    let bad_ref = st.update_task(r4, bad).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(39002).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}

#[test]
fn verified_reveal_success_version_conflict_does_not_unlock_worker_stake() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9899, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_balance("worker1", 40);

    let r1 = apply_create_task(&mut st, 19899, "alice".into(), 10).unwrap();
    let mut accepted_task = st.get_task(r1.id).unwrap();
    accepted_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, accepted_task).unwrap();

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(19899, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let mut completed_task = st.get_task(r3.id).unwrap();
    completed_task.status = TaskStatus::Completed;
    completed_task.result_hash = Some(result_hash);
    completed_task.reveal_salt = Some(reveal_salt);
    completed_task.challenge_deadline_height = None;
    completed_task.resolve_deadline_height = None;

    let stale_ref = r3.clone();
    let same_task = st.get_task(r3.id).unwrap();
    let _fresh_ref = st.update_task(r3, same_task).unwrap();

    let err = finalize_verified_reveal_success(&mut st, stale_ref, completed_task).unwrap_err();
    assert!(matches!(err, PouwError::VersionConflict));

    let task = st.get_task(19899).unwrap();
    assert_eq!(task.status, TaskStatus::Committed);
    assert!(task.result_hash.is_none());
    assert!(task.reveal_salt.is_none());
    assert_eq!(st.balance_of("worker1"), 0);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19899)), 40);
}

#[test]
fn verified_reveal_success_unlocks_worker_stake_after_task_update() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9900, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_balance("worker1", 40);

    let r1 = apply_create_task(&mut st, 19900, "alice".into(), 10).unwrap();
    let mut accepted_task = st.get_task(r1.id).unwrap();
    accepted_task.proof_type = ProofType::Tee;
    let r1 = st.update_task(r1, accepted_task).unwrap();

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [9u8; 32];
    let reveal_salt = [10u8; 32];
    let committed = compute_commitment(19900, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    let mut completed_task = st.get_task(r3.id).unwrap();
    completed_task.status = TaskStatus::Completed;
    completed_task.result_hash = Some(result_hash);
    completed_task.reveal_salt = Some(reveal_salt);
    completed_task.challenge_deadline_height = None;
    completed_task.resolve_deadline_height = None;

    let next_ref = finalize_verified_reveal_success(&mut st, r3, completed_task).unwrap();

    let task = st.get_task(19900).unwrap();
    assert_eq!(next_ref.version, task.version);
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.result_hash, Some(result_hash));
    assert_eq!(task.reveal_salt, Some(reveal_salt));
    assert_eq!(st.balance_of("worker1"), 40);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19900)), 0);
}
