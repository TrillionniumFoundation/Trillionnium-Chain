use super::*;

#[test]
fn resolve_slash_rejects_challenge_success_bounty_above_min_worker_stake_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1_000);
    st.set_gov_param_bootstrap_unchecked(9_991, "min_worker_stake".into(), "3".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_992, "challenge_success_bounty".into(), "4".into())
        .unwrap();
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 21_500;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_task = st.get_task(task_id).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(task_id));

    let err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
        1,
    )
    .expect_err("slash resolve must fail closed when bounty exceeds task-local slash principal");
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.pending_resolve_approval(r5.id), None);

    let after_task = st.get_task(task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(task_id)),
        before_lock
    );
}

#[test]
fn resolve_slash_rejects_challenge_success_bounty_above_task_bounty_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 1_000);
    st.set_gov_param_bootstrap_unchecked(9_993, "min_worker_stake".into(), "40".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9_994, "challenge_success_bounty".into(), "11".into())
        .unwrap();
    set_resolve_authority(&mut st, "authority,authority2");

    let task_id = 21_501;
    let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_task = st.get_task(task_id).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_worker = st.balance_of("worker1");
    let before_lock = st.balance_of(&worker_stake_lock_account(task_id));

    let err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
        1,
    )
    .expect_err("slash resolve must fail closed when bounty exceeds challenged task bounty");
    // The direct preflight unit test above pins the exact task-bounty diagnostic.
    // Here the end-to-end regression is focused on the stronger invariant:
    // oversized bounty configuration must abort the full resolve path without
    // mutating task state, escrow balances, or staged approvals.
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.pending_resolve_approval(r5.id), None);

    let after_task = st.get_task(task_id).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(st.balance_of("worker1"), before_worker);
    assert_eq!(
        st.balance_of(&worker_stake_lock_account(task_id)),
        before_lock
    );
}

#[test]
fn resolve_preflight_allows_challenge_success_bounty_equal_to_min_worker_stake() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9_502, "challenge_success_bounty".into(), "40".into())
        .expect("challenge success bounty governance seed must succeed");
    st.set_gov_param_bootstrap_unchecked(9_503, "min_worker_stake".into(), "40".into())
        .expect("min worker stake governance seed must succeed");

    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10);
    st.set_balance(&worker_stake_lock_account(75), 40);

    let task = TaskObject {
        task_id: 75,
        creator: "alice".into(),
        bounty: 40,
        status: TaskStatus::Slashed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    preflight_resolve_transfers(&st, &task, true).expect(
        "bounty equal to min_worker_stake should remain inside the allowed slash-principal envelope",
    );
}

#[test]
fn resolve_preflight_rejects_challenge_success_bounty_above_task_bounty() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9_504, "challenge_success_bounty".into(), "11".into())
        .expect("challenge success bounty governance seed must succeed");
    st.set_gov_param_bootstrap_unchecked(9_505, "min_worker_stake".into(), "40".into())
        .expect("min worker stake governance seed must succeed");

    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10);

    let task = TaskObject {
        task_id: 76,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Slashed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    let err = preflight_resolve_transfers(&st, &task, true).unwrap_err();
    match err {
        PouwError::State(msg) => {
            assert!(
                msg.contains("exceeds task bounty"),
                "unexpected state error: {msg}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn resolve_preflight_allows_challenge_success_bounty_equal_to_task_bounty() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9_506, "challenge_success_bounty".into(), "10".into())
        .expect("challenge success bounty governance seed must succeed");
    st.set_gov_param_bootstrap_unchecked(9_507, "min_worker_stake".into(), "40".into())
        .expect("min worker stake governance seed must succeed");

    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10);
    st.set_balance(&worker_stake_lock_account(77), 10);

    let task = TaskObject {
        task_id: 77,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Slashed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    preflight_resolve_transfers(&st, &task, true)
        .expect("bounty equal to task bounty should remain inside the allowed task-local envelope");
}

#[test]
fn resolve_preflight_rejects_challenge_success_bounty_above_task_local_slashable_stake() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9_508, "challenge_success_bounty".into(), "10".into())
        .expect("challenge success bounty governance seed must succeed");
    st.set_gov_param_bootstrap_unchecked(9_509, "min_worker_stake".into(), "40".into())
        .expect("min worker stake governance seed must succeed");

    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10);
    st.set_balance(&worker_stake_lock_account(78), 9);

    let task = TaskObject {
        task_id: 78,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Slashed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_lock = st.balance_of(&worker_stake_lock_account(78));
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = preflight_resolve_transfers(&st, &task, true).expect_err(
        "slash resolve preflight must fail closed when task-local slashable stake is underfunded",
    );
    match err {
        PouwError::State(msg) => {
            assert!(
                msg.contains("task-local slashable stake"),
                "unexpected state error: {msg}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(st.balance_of(&worker_stake_lock_account(78)), before_lock);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_slash_treasury
    );
}
