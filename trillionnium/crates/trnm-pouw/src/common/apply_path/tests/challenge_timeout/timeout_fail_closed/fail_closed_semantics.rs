use super::*;

#[test]
fn timeout_rejects_challenged_task_with_missing_challenger_metadata_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1_000);

    let task_id = 21_501;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let _ = apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, "challenger".into(), 1)
        .unwrap();

    let mut task = st.get_task(task_id).unwrap();
    task.challenger = None;
    let challenged_ref = st
        .update_task(
            ObjectRef {
                id: task_id,
                version: task.version,
            },
            task.clone(),
        )
        .unwrap();

    let before_task = st.get_task(task_id).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, challenged_ref, 999)
        .expect_err("timeout must fail closed when challenged task is missing challenger metadata");
    assert!(matches!(err, PouwError::State(_)));

    let after_task = st.get_task(task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(after_task.challenger, before_task.challenger);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}

#[test]
fn timeout_rejects_missing_resolve_deadline_without_clearing_staged_multisig_approval() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1_000);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let task_id = 21_503;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [6u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 =
        apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, "challenger".into(), 1)
            .unwrap();

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
        2,
    )
    .expect_err("first multisig resolve should only stage approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(task_id), Some((true, 1)));

    let mut task = st.get_task(task_id).unwrap();
    task.resolve_deadline_height = None;
    let bad_ref = st
        .update_task(
            ObjectRef {
                id: task_id,
                version: task.version,
            },
            task.clone(),
        )
        .unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, bad_ref, 999).expect_err(
        "timeout must fail closed when challenged task is missing resolve deadline metadata",
    );
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
    )));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.pending_resolve_approval(task_id),
        Some((true, 1)),
        "failed timeout must not clear staged resolve approval"
    );
    assert_eq!(
        st.pending_resolve_first_approver(task_id),
        Some("authority-a".to_string())
    );
}

#[test]
fn timeout_rejects_challenged_task_with_missing_resolve_deadline_without_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1_000);

    let task_id = 21_502;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [6u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let _ = apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, "challenger".into(), 1)
        .unwrap();

    let mut task = st.get_task(task_id).unwrap();
    task.resolve_deadline_height = None;
    let challenged_ref = st
        .update_task(
            ObjectRef {
                id: task_id,
                version: task.version,
            },
            task.clone(),
        )
        .unwrap();

    let before_task = st.get_task(task_id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(task_id));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, challenged_ref, 999).expect_err(
        "timeout must fail closed when challenged task is missing resolve deadline metadata",
    );
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
    )));

    let after_task = st.get_task(task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.resolve_deadline_height,
        before_task.resolve_deadline_height
    );
    assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(task_id)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenged_timeout_rejects_pre_forfeited_marker_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_117, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_118, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_119, "alice".into(), 10).unwrap();
    let result_hash = [6u8; 32];
    let reveal_salt = [10u8; 32];
    let committed = compute_commitment(40_119, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.challenge_bond_forfeited = Some(true);
    let bad_ref = st.update_task(r5, malformed).unwrap();

    let before_task = st.get_task(bad_ref.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_119));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("pre-forfeited challenged timeout metadata must fail closed");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged task cannot have terminal challenge bond outcome"
    )));

    let after_task = st.get_task(before_task.task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(
        after_task.resolve_deadline_height,
        before_task.resolve_deadline_height
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_119)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenged_timeout_rejects_missing_resolve_deadline_without_escrow_or_slash_treasury_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_120, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_121, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_122, "alice".into(), 10).unwrap();
    let result_hash = [11u8; 32];
    let reveal_salt = [12u8; 32];
    let committed = compute_commitment(40_122, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.resolve_deadline_height = None;
    let bad_ref = st.update_task(r5, malformed).unwrap();

    let before_task = st.get_task(bad_ref.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_122));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("missing resolve deadline must fail closed before timeout settlement");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
    )));

    let after_task = st.get_task(before_task.task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(
        after_task.resolve_deadline_height,
        before_task.resolve_deadline_height
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_122)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenged_timeout_rejects_missing_challenge_deadline_without_escrow_or_slash_treasury_mutation()
{
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_125, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_126, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_127, "alice".into(), 10).unwrap();
    let result_hash = [15u8; 32];
    let reveal_salt = [16u8; 32];
    let committed = compute_commitment(40_127, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.challenge_deadline_height = None;
    let bad_ref = st.update_task(r5, malformed).unwrap();

    let before_task = st.get_task(bad_ref.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_127));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("missing challenge deadline must fail closed before timeout settlement");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
    )));

    let after_task = st.get_task(before_task.task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_deadline_height,
        before_task.challenge_deadline_height
    );
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_127)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn challenged_timeout_rejects_missing_window_snapshot_without_escrow_or_slash_treasury_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_123, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(40_124, "challenge_success_bounty".into(), "1".into())
        .unwrap();
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 9);

    let r1 = apply_create_task(&mut st, 40_126, "alice".into(), 10).unwrap();
    let result_hash = [13u8; 32];
    let reveal_salt = [14u8; 32];
    let committed = compute_commitment(40_126, &result_hash, &reveal_salt, "worker1");
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

    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.challenge_window_blocks_snapshot = None;
    let bad_ref = st.update_task(r5, malformed).unwrap();

    let before_task = st.get_task(bad_ref.id).unwrap();
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(40_123));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("missing challenge window snapshot must fail closed before timeout settlement");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "challenged status requires challenge_window_blocks_snapshot"
    )));

    let after_task = st.get_task(before_task.task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_window_blocks_snapshot,
        before_task.challenge_window_blocks_snapshot
    );
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(40_123)),
        before_lock
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}

#[test]
fn completed_challenge_terminal_state_requires_retained_evidence_surface() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 40_128, "alice".into(), 10).unwrap();
    let result_hash = [15u8; 32];
    let reveal_salt = [16u8; 32];
    let committed = compute_commitment(40_128, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 10).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 20).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        30,
    )
    .unwrap();
    let completed_ref = apply_timeout(&mut st, r5, 131).unwrap();

    let completed = st.get_task(completed_ref.id).unwrap();
    validate_challenge_accounting_invariants(&completed)
        .expect("completed challenge timeout path must retain auditable evidence metadata");

    let mut missing_snapshot = completed.clone();
    missing_snapshot.challenge_window_blocks_snapshot = None;
    let err = validate_challenge_accounting_invariants(&missing_snapshot)
        .expect_err("terminal completed challenge state must fail closed without evidence snapshot");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "terminal challenged task missing challenge_window_blocks_snapshot"
    )));

    let mut missing_timing = completed;
    missing_timing.resolve_deadline_height = None;
    let err = validate_challenge_accounting_invariants(&missing_timing)
        .expect_err("terminal completed challenge state must fail closed without timing evidence");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "terminal challenged task missing challenge timing metadata"
    )));
}
