use super::*;

#[test]
fn invalid_transition_matrix_smoke() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let r1 = apply_create_task(&mut st, 99, "alice".into(), 10).unwrap();

    // OPEN: only accept is valid.
    assert!(matches!(
        apply_reveal_result(&mut st, r1.clone(), [1u8; 32], [2u8; 32], None).unwrap_err(),
        PouwError::InvalidTransition
    ));
    assert!(matches!(
        apply_challenge(
            &mut st,
            r1.clone(),
            "challenger".into(),
            10,
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));
    assert!(matches!(
        apply_resolve(
            &mut st,
            r1.clone(),
            false,
            "challenger".into(),
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    // ASSIGNED: reveal/challenge/resolve are invalid before commit.
    assert!(matches!(
        apply_reveal_result(&mut st, r2.clone(), [1u8; 32], [2u8; 32], None).unwrap_err(),
        PouwError::InvalidTransition
    ));
    assert!(matches!(
        apply_challenge(
            &mut st,
            r2.clone(),
            "challenger".into(),
            10,
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));
    assert!(matches!(
        apply_resolve(
            &mut st,
            r2.clone(),
            false,
            "challenger".into(),
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(99, &result_hash, &reveal_salt, "worker1");
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

    // COMMITTED: challenge/resolve invalid before reveal.
    assert!(matches!(
        apply_challenge(
            &mut st,
            r3.clone(),
            "challenger".into(),
            10,
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));
    assert!(matches!(
        apply_resolve(
            &mut st,
            r3.clone(),
            false,
            "challenger".into(),
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));

    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    // REVEALED: resolve invalid before challenge.
    assert!(matches!(
        apply_resolve(
            &mut st,
            r4.clone(),
            false,
            "challenger".into(),
            "challenger".into()
        )
        .unwrap_err(),
        PouwError::InvalidTransition
    ));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    set_resolve_authority(&mut st, "authority,authority2");
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority2".into(),
        "authority2".into(),
    )
    .unwrap();

    // FINAL: further resolve is invalid when attempted against the current terminal ref.
    assert!(matches!(
        apply_resolve(&mut st, r6, false, "challenger".into(), "challenger".into()).unwrap_err(),
        PouwError::InvalidTransition
    ));
}
#[test]
fn stable_error_code_mapping() {
    assert_eq!(
        PouwError::InvalidTransition.stable_code(),
        "InvalidTransition"
    );
    assert_eq!(PouwError::VersionConflict.stable_code(), "VersionConflict");
    assert_eq!(PouwError::MissingWorker.stable_code(), "MissingWorker");
    assert_eq!(
        PouwError::MissingCommitment.stable_code(),
        "MissingCommitment"
    );
    assert_eq!(
        PouwError::CommitmentMismatch.stable_code(),
        "CommitmentMismatch"
    );
    assert_eq!(PouwError::Unauthorized.stable_code(), "Unauthorized");
    assert_eq!(
        PouwError::InsufficientStake.stable_code(),
        "InsufficientStake"
    );
    assert_eq!(
        PouwError::DeadlineExceeded.stable_code(),
        "DeadlineExceeded"
    );
    assert_eq!(PouwError::State("x".into()).stable_code(), "StateInternal");
}
