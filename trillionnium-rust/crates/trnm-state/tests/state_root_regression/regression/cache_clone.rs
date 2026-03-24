use super::*;

#[test]
fn cloned_cached_state_restore_roundtrip_rewinds_state_root_without_aliasing_original_cache() {
    let mut original = StateStore::new();
    original.set_balance("treasury.challenge_forfeits", 11);
    original.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_801,
            key: "challenge_min_bond".into(),
            value: "25".into(),
            activate_at_height: 40,
        }),
    );
    original.restore_pending_resolve_approval(
        5_401,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    original.restore_monetary_state(MonetaryState {
        last_tick_height: 9,
        tick_count: 2,
        total_minted: 13,
        total_burned: 5,
        net_issuance: 8,
    });

    let baseline_root = original.state_root();
    let mut cloned = original.clone();
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "cloned state should preserve the canonical cached root before any mutation"
    );

    let pending_snapshot = cloned.pending_gov_update("challenge_min_bond");
    let resolve_snapshot = cloned.pending_resolve_approval_snapshot(5_401);
    let balance_snapshot = Some(cloned.balance_of("treasury.challenge_forfeits"));
    let monetary_snapshot = cloned.monetary_state_snapshot();

    cloned.set_balance("treasury.challenge_forfeits", 19);
    cloned.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_801,
            key: "challenge_min_bond".into(),
            value: "31".into(),
            activate_at_height: 44,
        }),
    );
    cloned.restore_pending_resolve_approval(
        5_401,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "authority.beta".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 4,
        }),
    );
    cloned.restore_monetary_state(MonetaryState {
        last_tick_height: 12,
        tick_count: 3,
        total_minted: 21,
        total_burned: 9,
        net_issuance: 12,
    });

    let mutated_clone_root = cloned.state_root();
    assert_ne!(
        mutated_clone_root, baseline_root,
        "mutating the clone after the cached root has been copied must invalidate and recompute the clone root"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "clone-local mutations must not alias back into the original state's cached root"
    );

    cloned.restore_balance("treasury.challenge_forfeits", balance_snapshot);
    cloned.restore_pending_gov_update("challenge_min_bond", pending_snapshot);
    cloned.restore_pending_resolve_approval(5_401, resolve_snapshot);
    cloned.restore_monetary_state(monetary_snapshot);

    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "restoring the cloned cached state must rewind state_root exactly to the original canonical baseline"
    );
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "repeated reads after clone-local restore should deterministically reuse the rewound cached root"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "the original state's cached root must remain canonical after the clone completes its restore roundtrip"
    );
}
