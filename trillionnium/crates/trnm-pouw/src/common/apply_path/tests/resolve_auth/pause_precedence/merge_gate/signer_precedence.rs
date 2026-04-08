use super::*;

#[test]
fn resolve_multisig_member_reopens_after_emergency_pause_clears_without_escrow_drift() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_965, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_965, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_214, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("emergency pause must freeze multisig-member resolve path");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "paused resolve attempt must not stage multisig approvals",
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );

    st.set_gov_param(9_215, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("first multisig member must stage resolve after pause clears");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        Some((true, 1)),
        "post-pause first signer should stage exactly one slashing approval",
    );

    let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect("second multisig member must finalize resolve after pause clears");
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    assert_eq!(st.balance_of("challenger"), 101);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury.saturating_sub(1)
    );
}
#[test]
fn resolve_multisig_pending_approval_remains_staged_across_emergency_pause() {
    // Safety boundary: emergency pause must freeze terminal settlement even when
    // one multisig approval is already staged, without mutating escrow balances.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_966, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_966, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let worker_lock_account = worker_stake_lock_account(r5.id);
    let total_funds = |st: &StateStore| {
        st.balance_of("challenger")
            + st.balance_of("worker1")
            + st.balance_of(&worker_lock_account)
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
            + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
    };
    let baseline_total = total_funds(&st);

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("first multisig member must stage a pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(total_funds(&st), baseline_total);

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.set_gov_param(9_216, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("emergency pause must block final multisig settlement with pending approval");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash_treasury
    );

    st.set_gov_param(9_217, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect("second distinct signer must finalize once pause clears");
    assert_eq!(st.pending_resolve_approval(r6.id), None);

    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(total_funds(&st), baseline_total);
}
#[test]
fn resolve_multisig_rejects_decision_flip_after_pause_clear_without_escrow_mutation() {
    // Governance hardening: once a multisig slash decision is staged, reopening
    // after emergency pause clear must not allow slash/non-slash decision flips.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_967, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_967, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority2".into(),
        "authority2".into(),
    )
    .expect_err("first multisig member must stage slash decision");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    st.set_gov_param(9_218, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    st.set_gov_param(9_219, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let flip_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("second signer must not be able to flip staged slash decision after pause clear");
    assert!(matches!(flip_err, PouwError::Unauthorized));

    assert_eq!(st.pending_resolve_approval(r5.id), None);
    assert_eq!(st.pending_resolve_first_approver(r5.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let restaged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
    )
    .expect_err(
        "after decision flip clears staging, quorum must restart from a fresh first approval",
    );
    assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority")
    );

    let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into())
        .expect("fresh second signer should finalize restarted slash quorum after pause clear");
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
