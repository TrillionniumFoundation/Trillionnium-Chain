use super::*;

#[test]
fn challenge_rejected_after_reveal_deadline_window() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9101, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 901, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(901, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

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
fn challenge_accepted_at_reveal_deadline_boundary() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9102, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 902, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(902, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
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
    assert_eq!(task.status, TaskStatus::Challenged);
}

#[test]
fn challenge_rejects_resolve_deadline_height_overflow() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 903, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(903, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut near_overflow = st.get_task(r4.id).unwrap();
    near_overflow.challenge_deadline_height = Some(u64::MAX);
    near_overflow.challenge_window_blocks_snapshot = Some(1);
    let r4 = st.update_task(r4, near_overflow).unwrap();

    let err = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        u64::MAX,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
}

#[test]
fn challenge_clamps_malformed_legacy_zero_snapshot_to_minimum_block() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 91020, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(91020, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut malformed = st.get_task(r4.id).unwrap();
    malformed.challenge_window_blocks_snapshot = Some(0);
    let r4 = st.update_task(r4, malformed).unwrap();

    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        111,
    )
    .unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_window_blocks_snapshot, Some(1));
    assert_eq!(task.resolve_deadline_height, Some(112));
}

#[test]
fn legacy_snapshotless_revealed_is_rejected_on_live_challenge_when_gov_missing() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 91021, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(91021, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    // Simulate pre-snapshot legacy Revealed task persisted before rollout.
    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    // Do not seed challenge_window_blocks governance: live path should now reject
    // snapshotless legacy Revealed state instead of reviving fallback authority.
    let err = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        111,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("snapshotless revealed task requires migration replay/import path")));
}

#[test]
fn legacy_snapshotless_revealed_still_allows_height_zero_replay_import_path() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9134, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19134, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19134, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
        .unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_window_blocks_snapshot, Some(300));
    assert_eq!(task.status, TaskStatus::Challenged);
}

#[test]
fn challenge_live_path_rejects_snapshotless_legacy_revealed_after_governance_change() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9135, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19135, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19135, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut legacy = st.get_task(r4.id).unwrap();
    legacy.challenge_window_blocks_snapshot = None;
    let r4 = st.update_task(r4, legacy).unwrap();
    let task_id = r4.id;

    st.set_gov_param_bootstrap_unchecked(9135, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let err = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        210,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("snapshotless revealed task requires migration replay/import path")));

    let task = st.get_task(task_id).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenge_window_blocks_snapshot, None);
    assert_eq!(st.balance_of("challenger"), 100);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
}

#[test]
fn challenge_window_is_snapshotted_at_reveal_even_if_governance_changes_after() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9110, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19110, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19110, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    st.set_gov_param_bootstrap_unchecked(9110, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let err = apply_challenge_at_height(
        &mut st,
        r4.clone(),
        "challenger".into(),
        10,
        "challenger".into(),
        211,
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::DeadlineExceeded));

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
    assert_eq!(task.challenge_window_blocks_snapshot, Some(100));
    assert_eq!(task.resolve_deadline_height, Some(310));
}

#[test]
fn challenge_boundary_stays_correct_at_and_after_deadline_with_snapshot() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9120, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 19120, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19120, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    st.set_gov_param_bootstrap_unchecked(9120, "challenge_window_blocks".into(), "300".into())
        .unwrap();

    let r5 = apply_challenge_at_height(
        &mut st,
        r4.clone(),
        "challenger".into(),
        10,
        "challenger".into(),
        210,
    )
    .unwrap();
    let before_resolve_timeout = apply_timeout(&mut st, r5.clone(), 310).unwrap_err();
    assert!(matches!(
        before_resolve_timeout,
        PouwError::InvalidTransition
    ));

    let r6 = apply_timeout(&mut st, r5, 311).unwrap();
    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
}

#[test]
fn default_challenge_window_meets_governance_minimum_floor() {
    assert!(DEFAULT_CHALLENGE_WINDOW_BLOCKS >= 100);
}

#[test]
fn challenge_uses_default_window_when_governance_absent() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 893, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(893, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let challenged = st.get_task(r5.id).unwrap();
    assert_eq!(
        challenged.resolve_deadline_height,
        Some(120 + DEFAULT_CHALLENGE_WINDOW_BLOCKS)
    );
}

#[test]
fn challenge_uses_governance_window_and_resolve_marks_bond_outcome() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9002, "challenge_window_blocks".into(), "123".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 889, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(889, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let challenged = st.get_task(r5.id).unwrap();
    assert_eq!(challenged.resolve_deadline_height, Some(243));
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

    set_resolve_authority(&mut st, "authority,authority2");
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("first resolver should stage multisig approval");
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();
    let resolved = st.get_task(r6.id).unwrap();
    assert_eq!(resolved.challenge_bond_forfeited, Some(true));
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
}
