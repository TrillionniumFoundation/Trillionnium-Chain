use super::*;

#[test]
fn resolve_multisig_rejects_stale_first_approver_after_governance_member_rotation_without_escrow_mutation(
) {
    // Governance hardening: once signer membership rotates, previously staged
    // approvals from removed members must be discarded before settlement.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

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

    // Rotate signer set: remove staged approver and add a new member.
    set_resolve_authority(&mut st, "authority-b,authority-c");

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("stale staged approver from removed member must be discarded");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "stale staged approval should be cleared after authority-set rotation",
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
fn resolve_multisig_rotation_that_keeps_first_member_still_clears_stale_staging_before_escrow_settlement(
) {
    // Governance hardening: any signer-set rotation must invalidate prior staged approvals,
    // even if the original first approver remains in the new multisig set.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_970, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_970, &result_hash, &reveal_salt, "worker1");

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

    // Rotate membership while keeping authority-a present.
    set_resolve_authority(&mut st, "authority-a,authority-c");

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-c".into(),
        "authority-c".into(),
    )
    .expect_err("rotation must clear stale staged approval even when first signer remains in set");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "any authority-set rotation must clear stale staged approvals",
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
        "authority-a".into(),
        "authority-a".into(),
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
    .expect("second signer in rotated set should finalize terminal settlement");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_multisig_task_version_change_clears_stale_staging_before_terminal_settlement() {
    // Economic snapshot hardening: second multisig finalize must bind to the
    // challenged task version captured at first approval. Any intervening task
    // mutation should clear stale staging and require a fresh quorum.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_972, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_972, &result_hash, &reveal_salt, "worker1");

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
    .expect_err("first multisig signer should stage before terminal settlement");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let task = st.get_task(r5.id).expect("challenged task must exist");
    let r5_mut = st
        .update_task(r5.clone(), task)
        .expect("intervening task rewrite should bump version");
    assert!(r5_mut.version > r5.version);

    let stale_err = apply_resolve(
        &mut st,
        r5_mut.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("task-version drift must clear stale staged approval");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "task-version drift must clear stale staged approval",
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    let restaged_err = apply_resolve(
        &mut st,
        r5_mut.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("fresh first signer should restage after stale approval clears");
    assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    let r6 = apply_resolve(
        &mut st,
        r5_mut,
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect("second signer should finalize after fresh staging on new version");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond, Some(10));
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_multisig_member_reordering_preserves_staging_before_terminal_settlement() {
    // Canonical-configuration hardening: authority-set member reordering is now treated as a
    // semantically equivalent governance boundary, so an already staged approval must remain
    // valid for a distinct second signer instead of being scrubbed.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_976, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_976, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let staged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("first multisig signer should stage before terminal settlement");
    assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

    // Reorder members without changing member identities.
    set_resolve_authority(&mut st, "authority-b,authority-a");

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect("reordered authority set should preserve staged approval for a distinct signer");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_multisig_to_single_authority_rotation_clears_stale_staging_before_terminal_settlement() {
    // Minimal multi-party control: downgrading resolver membership from multisig
    // to single authority must fail closed by clearing stale staged approvals,
    // and governance must restage a fresh quorum if multisig is later restored.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority-a,authority-b");

    let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

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

    set_resolve_authority(&mut st, "authority-a");

    let singleton_followup = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect_err("singleton downgrade must reject inherited staged multisig approval");
    assert!(matches!(singleton_followup, PouwError::Unauthorized));
    assert_eq!(
        st.pending_resolve_approval(r5.id),
        None,
        "singleton downgrade must clear stale staged approval",
    );
    assert_eq!(
        st.pending_resolve_first_approver(r5.id),
        None,
        "singleton downgrade must clear stale first approver metadata",
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);

    set_resolve_authority(&mut st, "authority-a,authority-b");

    let restaged_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("restored multisig must start from a fresh staged approval");
    assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-b")
    );

    let r6 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority-a".into(),
        "authority-a".into(),
    )
    .expect("restored multisig should finalize only after a fresh distinct second approval");
    assert_eq!(st.pending_resolve_approval(r6.id), None);
    let task = st.get_task(r6.id).expect("resolved task must persist");
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
}
#[test]
fn resolve_multisig_clears_staged_approval_on_case_drifted_member_rotation_without_escrow_mutation()
{
    // Canonical-account hardening: signer membership uses exact account IDs,
    // so case-drifted rotations must clear staged approvals fail-closed.
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

    // Rotate with case drift for the first approver ID.
    set_resolve_authority(&mut st, "Authority-A,authority-b");

    let stale_err = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority-b".into(),
        "authority-b".into(),
    )
    .expect_err("case-drifted membership rotation must clear staged approval fail-closed");
    assert!(matches!(stale_err, PouwError::Unauthorized));
    assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "staged approval should be cleared when first approver account id no longer matches exactly",
        );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
