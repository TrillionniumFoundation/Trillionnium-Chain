use super::*;

#[test]
fn challenge_escrow_treasury_balance_must_affect_state_root_even_when_other_treasury_and_monetary_fields_match(
) {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    for state in [&mut state_a, &mut state_b] {
        state.set_balance("treasury.challenge_forfeits", 11);
        state.set_balance("treasury.worker_slashes", 7);
        state.restore_pending_gov_update(
            "challenge_min_bond",
            Some(PendingGovParamUpdate {
                key_id: 301,
                key: "challenge_min_bond".into(),
                value: "120".into(),
                activate_at_height: 250,
            }),
        );
        state.restore_pending_resolve_approval(
            4_199,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority.alpha".into(),
                authority_set: "authority.alpha,authority.beta".into(),
                task_version: 3,
            }),
        );
        state.restore_monetary_state(MonetaryState {
            last_tick_height: 90,
            tick_count: 4,
            total_minted: 21,
            total_burned: 5,
            net_issuance: 16,
        });
    }

    let baseline_root = state_a.state_root();
    assert_eq!(
        baseline_root,
        state_b.state_root(),
        "sanity: equivalent baseline pending/treasury/monetary state should hash identically"
    );

    state_b.set_balance("treasury.challenge_escrow", 13);

    assert_ne!(
        baseline_root,
        state_b.state_root(),
        "state_root must include the canonical treasury.challenge_escrow balance so challenge escrow accounting cannot be omitted while other treasury and monetary fields remain unchanged"
    );

    state_b.restore_balance("treasury.challenge_escrow", None);
    assert_eq!(
        baseline_root,
        state_b.state_root(),
        "restoring the absent challenge escrow slot must rewind the deterministic root exactly"
    );
}
