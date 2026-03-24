use super::*;

#[test]
fn challenged_timeout_rejects_while_paused_and_preserves_multisig_staging_until_unpaused() {
    // Safety boundary: emergency pause must fail-closed before challenged-task
    // timeout finalization so staged multisig resolve approvals and escrow
    // custody remain frozen until governance explicitly unpauses.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19_122, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_122, &result_hash, &reveal_salt, "worker1");

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

    let staged_err = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first multisig signer should only stage pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    st.set_gov_param(9_222, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(r5.id).expect("challenged task must persist");
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let paused_err = apply_timeout(&mut st, r5.clone(), 311)
        .expect_err("emergency pause must freeze challenged timeout settlement path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let after_paused_task = st
        .get_task(r5.id)
        .expect("task must remain unchanged while paused");
    assert_eq!(after_paused_task.status, before_task.status);
    assert_eq!(
        after_paused_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_223, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_timeout(&mut st, r5, 311)
        .expect("challenged timeout should finalize once emergency pause clears");
    let task = st.get_task(r6.id).expect("timed out task must exist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    assert_eq!(st.pending_resolve_first_approver(r6.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
}

#[test]
fn challenged_timeout_allows_uncontested_revealed_finalization_while_paused() {
    // Safety boundary scope: emergency pause should freeze challenged escrow
    // settlement only; uncontested reveal timeout finalization must remain live.
    let mut st = seeded_state();
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 19_121, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(19_121, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    st.set_gov_param(9_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let r5 = apply_timeout(&mut st, r4, 211)
        .expect("uncontested reveal timeout should finalize even while paused");
    let task = st.get_task(r5.id).expect("task must exist after timeout");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.pending_resolve_approval(r5.id), None);
    assert_eq!(st.pending_resolve_first_approver(r5.id), None);

    // No challenged escrow path was entered; custodial balances remain unchanged.
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );
}

#[test]
fn challenge_rejects_while_emergency_pause_active_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_969, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_969, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    st.set_gov_param(9_206, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_969).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
        .expect_err("emergency pause must freeze challenge escrow entry path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_969).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(after_task.challenger, before_task.challenger);
    assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn challenge_emergency_pause_precedes_bond_checks_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before economic
    // min-bond gates so paused challenge flow cannot leak bond-policy outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    st.set_gov_param_bootstrap_unchecked(9_209, "challenge_min_bond".into(), "50".into())
        .expect("challenge_min_bond governance seed must succeed");

    let r1 = apply_create_task(&mut st, 8_971, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_971, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    st.set_gov_param(9_210, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_971).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
        .expect_err("emergency pause must mask min-bond result and freeze challenge entry path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_971).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(after_task.challenger, before_task.challenger);
    assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn challenge_emergency_pause_precedes_challenger_signer_auth_checks_without_escrow_mutation() {
    // Merge-gate hardening: pause guard must fire before challenger/signer
    // identity validation so paused challenge flow cannot leak auth-policy outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_971_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_971_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    st.set_gov_param(9_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_971_1).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "authority".into()).expect_err(
        "emergency pause must mask challenger/signer mismatch and freeze challenge entry path",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_971_1).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(after_task.challenger, before_task.challenger);
    assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn challenge_reopens_after_emergency_pause_clears() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_970, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_970, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    st.set_gov_param(9_207, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        10,
        "challenger".into(),
    )
    .expect_err("emergency pause must freeze challenge entry path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 100);

    st.set_gov_param(9_208, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
        .expect("challenge must reopen after emergency pause is cleared");

    let task = st.get_task(r5.id).expect("challenged task must persist");
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenger.as_deref(), Some("challenger"));
    assert_eq!(task.challenge_bond, Some(10));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of("challenger"), 90);
}

#[test]
fn timeout_rejects_challenged_path_while_emergency_pause_active_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_962, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_202, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_962).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, r5, 221)
        .expect_err("emergency pause must freeze challenged timeout settlement path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_962).unwrap();
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
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn timeout_emergency_pause_preserves_staged_multisig_resolve_approval_without_escrow_mutation() {
    // Safety boundary: emergency pause must fail-closed for challenged timeout
    // settlement even when a multisig resolve approval is already staged.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_962_09, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_09, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("first multisig signer must stage resolve approval before timeout");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    st.set_gov_param(9_202_09, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_962_09).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, r5.clone(), 221).expect_err(
        "emergency pause must freeze challenged timeout despite staged multisig approval",
    );
    assert!(matches!(err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let after_task = st.get_task(8_962_09).unwrap();
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
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_202_10, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let done = apply_timeout(&mut st, r5, 221)
        .expect("challenged timeout should reopen after pause clear and finalize once");
    assert_eq!(st.pending_resolve_approval(done.id), None);
}

#[test]
fn timeout_emergency_pause_precedes_challenged_invariant_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before challenged
    // accounting invariant checks to avoid leaking escrow-state validation paths.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Corrupt challenged object to violate timeout challenged-accounting invariants.
    let mut bad = st.get_task(r5.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Challenged);
    bad.challenge_bond_forfeited = Some(false);
    let bad_ref = st.update_task(r5, bad).unwrap();

    st.set_gov_param(9_202_3, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_962_1).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, bad_ref, 221)
        .expect_err("emergency pause must mask challenged invariant validation path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_962_1).unwrap();
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
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn timeout_emergency_pause_precedes_deadline_checks_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before timeout
    // deadline checks so challenged timeout flow cannot leak liveness outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_962_4, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_4, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_202_4, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_962_4).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_timeout(&mut st, r5, 0)
        .expect_err("emergency pause must mask deadline checks and freeze challenged timeout path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_962_4).unwrap();
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
    assert_eq!(st.balance_of("challenger"), before_challenger);
}

#[test]
fn timeout_reopens_after_emergency_pause_clears_with_single_settlement() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_202_1, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_timeout(&mut st, r5.clone(), 221)
        .expect_err("emergency pause must freeze challenged timeout settlement path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 90);

    st.set_gov_param(9_202_2, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let done = apply_timeout(&mut st, r5, 221)
        .expect("challenged timeout must reopen after emergency pause clears");
    let task = st.get_task(done.id).expect("timed out task must persist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 100);

    let escrow_after_first_timeout = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeit_after_first_timeout = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let challenger_after_first_timeout = st.balance_of("challenger");

    let replay_err = apply_timeout(&mut st, done, 221)
        .expect_err("terminal timeout replay must be rejected without double settlement");
    assert!(matches!(replay_err, PouwError::InvalidTransition));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        escrow_after_first_timeout
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeit_after_first_timeout
    );
    assert_eq!(st.balance_of("challenger"), challenger_after_first_timeout);
}

#[test]
fn timeout_revealed_path_remains_available_while_emergency_pause_active() {
    let mut st = seeded_state();

    let r1 = apply_create_task(&mut st, 8_963, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_963, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    st.set_gov_param(9_203, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let next = apply_timeout(&mut st, r4, 10_000)
        .expect("emergency pause must not block non-challenged timeout completion path");

    let task = st
        .get_task(next.id)
        .expect("revealed timeout completion must persist task object");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(task.challenge_bond_forfeited, None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );
}
