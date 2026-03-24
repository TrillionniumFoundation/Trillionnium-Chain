use super::*;

#[test]
fn resolve_multisig_rotation_during_emergency_pause_clears_stale_approval_only_after_unpause() {
    // Safety boundary + governance hardening: pause must fail-closed before
    // multisig membership checks, and stale staged approvals must be cleared
    // only once resolve flow re-opens after unpause.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_969, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_969, &result_hash, &reveal_salt, "worker1");

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
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig signer should only stage pending approval");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    st.set_gov_param(9_219_30, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    // Rotate membership while paused to remove the staged first approver.
    set_resolve_authority(&mut st, "authority-b,authority-c");

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("pause must fail-closed before multisig membership-change handling");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        Some((true, 1)),
        "paused resolve attempt must not clear staged approvals",
    );

    st.set_gov_param(9_219_31, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("unpaused resolve should clear stale staged approver removed by rotation");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "stale staged approval should clear once membership checks resume",
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let staged_again_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("first signer in rotated set should re-stage from empty state");
    assert!(matches!(staged_again_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-c".into(),
        "authority-c".into(),
    )
    .expect("second rotated signer should finalize terminal settlement");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_multisig_rotation_during_emergency_pause_clears_stale_completed_path_without_escrow_drift(
) {
    // Safety boundary + governance hardening: paused challenged-resolve flow
    // must freeze staged approvals, then clear stale approvals after unpause
    // even for slash=false (forfeit-treasury) settlement path.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_969_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_969_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");
    let before_total = before_escrow + before_forfeit + before_challenger;

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig signer should stage pending approval for slash=false path");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

    st.set_gov_param(9_219_32, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    set_resolve_authority(&mut st, "authority-b,authority-c");

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("pause must fail-closed before slash=false membership rotation handling");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

    st.set_gov_param(9_219_33, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("unpaused slash=false resolve should clear stale staged approver");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_approval(r5.id), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let restaged_err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("rotated slash=false signer should re-stage from empty state");
    assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

    let r6 = apply_resolve(
        &mut st,
        r5,
        false,
        "authority-c".into(),
        "authority-c".into(),
    )
    .expect("second rotated signer should finalize slash=false settlement");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, Some(true));
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit + 10
    );
    let after_total = st.balance_of("challenger")
        + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    assert_eq!(
        after_total, before_total,
        "slash=false rotation/unpause resolve must conserve challenger+escrow+forfeit totals"
    );
}
