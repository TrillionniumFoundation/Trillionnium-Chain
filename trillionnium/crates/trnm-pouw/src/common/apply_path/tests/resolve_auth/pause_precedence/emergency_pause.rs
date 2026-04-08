use super::*;

#[test]
fn resolve_rejects_while_emergency_pause_active_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_960, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_960, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let pause = st
        .set_gov_param(9_200, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(matches!(
        pause,
        trnm_state::GovParamUpdateOutcome::Applied(_)
    ));
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_960).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("emergency pause must freeze terminal challenge resolution");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_960).unwrap();
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
fn resolve_pause_boundary_precedes_authority_validation_without_escrow_mutation() {
    // Safety boundary: emergency pause must fail-closed before authority
    // validation so malformed resolver payloads cannot leak auth-policy outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_960_5, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_960_5, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_200_5, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_960_5).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority".into(),
        "authority;spoof".into(),
    )
    .expect_err("pause boundary must trigger before malformed signer validation");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_960_5).unwrap();
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
fn resolve_rejects_non_slashing_path_while_emergency_pause_active_without_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_961, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
        .expect_err("emergency pause must freeze non-slashing challenge resolution path too");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961).unwrap();
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
fn resolve_multisig_paused_after_first_approval_preserves_staged_authority_and_escrow_until_unpaused(
) {
    // Safety boundary: pause must fail-closed before multisig confirmation so
    // staged approvals remain intact and escrow cannot settle while paused.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_961_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_2, &result_hash, &reveal_salt, "worker1");

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
    .expect_err("first multisig approval should stage only");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(9_201_2, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("pause must block second multisig approval and terminal settlement");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_201_3, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect("second multisig signer should finalize after pause clears");
    let task = st.get_task(r6.id).expect("resolved task must exist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(st.pending_resolve_first_approver(r5.id), None);
}
#[test]
fn resolve_pause_masks_authority_rotation_until_unpause_then_clears_stale_multisig_approval() {
    // Governance + safety hardening: emergency pause must mask signer-set
    // rotation effects while active, then fail closed after unpause by clearing
    // now-stale staged approvals before any escrow settlement path can proceed.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_961_16, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_16, &result_hash, &reveal_salt, "worker1");

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
    .expect_err("first multisig approval should stage only");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(9_201_16, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());
    set_resolve_authority(&mut st, "authority-b,authority-c");

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-c".into(),
        "authority-c".into(),
    )
    .expect_err("pause must mask rotated signer-set checks and freeze settlement");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_201_17, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let stale_err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-c".into(),
        "authority-c".into(),
    )
    .expect_err("stale first approver must be cleared after signer-set rotation");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(st.pending_resolve_first_approver(8_961_16), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_pause_masks_single_authority_downgrade_until_unpause_then_clears_staged_multisig() {
    // Governance + decentralization hardening: pause must keep already-staged
    // multisig approvals intact, then after unpause a downgraded single-authority
    // resolver config must fail closed and clear stale staging without escrow drift.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_961_17, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_17, &result_hash, &reveal_salt, "worker1");

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
    .expect_err("first multisig approval should stage only");
    assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(9_201_18, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());
    set_resolve_authority(&mut st, "authority-b");

    let paused_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("pause must mask downgrade effects and freeze challenged settlement");
    assert!(matches!(paused_err, PouwError::InvalidTransition));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    st.set_gov_param(9_201_19, 7_999, "emergency_pause".into(), "false".into())
        .expect("pause=false governance update must succeed");
    assert!(!st.is_emergency_paused());

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect("singleton downgrade must be rejected, leaving multisig settlement available");
    assert_eq!(st.pending_resolve_first_approver(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert!(st.balance_of("challenger") >= before_challenger);
}
