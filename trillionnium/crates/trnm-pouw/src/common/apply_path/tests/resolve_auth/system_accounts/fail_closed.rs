use super::*;

#[test]
fn challenged_resolve_rejects_missing_window_snapshot_without_escrow_or_slash_treasury_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance("worker1", 40);
    st.set_gov_param_bootstrap_unchecked(40_125, "min_worker_stake".into(), "40".into())
        .unwrap();
    set_resolve_authority(&mut st, "resolver1");

    let r1 = apply_create_task(&mut st, 40_124, "alice".into(), 10).unwrap();
    let result_hash = [15u8; 32];
    let reveal_salt = [16u8; 32];
    let committed = compute_commitment(40_124, &result_hash, &reveal_salt, "worker1");
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
    let before_lock = st.balance_of(&worker_stake_lock_account(40_124));
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = apply_resolve_at_height(
        &mut st,
        bad_ref,
        true,
        "resolver1".into(),
        "resolver1".into(),
        121,
    )
    .expect_err("missing challenge window snapshot must fail closed before resolve settlement");
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
        st.balance_of(&worker_stake_lock_account(40_124)),
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

fn resolve_preflight_rejects_forfeit_without_challenger() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 76,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Challenged,
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
        challenger: None,
        version: 0,
    };

    let err = preflight_resolve_transfers(&st, &task, false).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
}
