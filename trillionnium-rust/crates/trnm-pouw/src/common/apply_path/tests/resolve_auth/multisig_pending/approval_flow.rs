use super::*;

#[test]
fn resolve_multisig_requires_two_distinct_approvers_before_terminal_settlement() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 895_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(895_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let first_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig approver must not finalize resolve");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect("second distinct multisig approver should finalize resolve");
    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 101);
}
#[test]
fn resolve_multisig_rejects_replayed_first_approver_without_escrow_mutation() {
    // Minimal multi-party control: a staged approval from signer A must still
    // require a distinct signer B; signer A cannot replay approval to finalize.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 895_1_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(895_1_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let first_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig approver must only stage pending approval");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let replay_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("replayed first multisig approver must not finalize resolve");
    assert!(matches!(replay_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_multisig_rejects_decision_flip_and_clears_stale_staged_approval_without_escrow_mutation()
{
    // Economic + governance hardening: once one multisig signer stages a
    // slashing/non-slashing decision, a second signer cannot flip that
    // terminal settlement decision in-flight. Fail closed by clearing the
    // stale staged approval so governance must restart from a clean quorum.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 895_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(895_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let first_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first signer must only stage slashing resolve approval");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let decision_flip_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("second signer must not flip staged slashing decision to non-slashing");
    assert!(matches!(decision_flip_err, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "decision mismatch must clear stale staged multisig approval",
    );
    assert_eq!(
        st.pending_resolve_first_approver(r5.id),
        None,
        "decision mismatch must clear stale first approver metadata",
    );

    let task = st
        .get_task(r5.id)
        .expect("challenged task must remain in state after decision mismatch");
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury,
    );
}
