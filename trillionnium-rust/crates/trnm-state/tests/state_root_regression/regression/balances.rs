use super::*;

#[test]
fn restore_balance_none_rewinds_state_root_after_removing_existing_treasury_entry() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.set_balance("treasury.challenge_forfeits", 11);
    let balance_snapshot = None;
    let funded_root = state.state_root();
    assert_ne!(
        funded_root, baseline_root,
        "sanity: adding a treasury balance entry must perturb the state root"
    );

    state.restore_balance("treasury.challenge_forfeits", balance_snapshot);

    assert_eq!(
        state.balance_of("treasury.challenge_forfeits"),
        0,
        "restoring a missing balance snapshot should remove the treasury entry"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_balance(None) must rewind state_root exactly after deleting a previously added treasury entry"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_balance(None) should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_balance_rewinds_state_root_after_value_mutation() {
    let mut state = StateStore::new();

    state.set_balance("treasury.challenge_forfeits", 25);
    let baseline_snapshot = Some(state.balance_of("treasury.challenge_forfeits"));
    let root_before = state.state_root();

    state.set_balance("treasury.challenge_forfeits", 40);
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate treasury balance amounts so distinct funded values cannot hash identically"
    );

    state.restore_balance("treasury.challenge_forfeits", baseline_snapshot);

    assert_eq!(
        state.balance_of("treasury.challenge_forfeits"),
        25,
        "restore_balance(Some(amount)) should restore the prior treasury balance amount"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "restore_balance(Some(amount)) must rewind state_root exactly after a treasury balance value mutation"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after restore_balance(Some(amount)) should deterministically reuse the rewound cached root"
    );
}
#[test]
fn restore_balance_zero_snapshot_canonicalizes_to_missing_entry_for_state_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.set_balance("treasury.challenge_forfeits", 11);
    let funded_root = state.state_root();
    assert_ne!(
        funded_root, baseline_root,
        "sanity: funding a treasury entry must perturb the state root"
    );

    state.restore_balance("treasury.challenge_forfeits", Some(0));

    assert_eq!(
        state.balance_of("treasury.challenge_forfeits"),
        0,
        "restoring a zero-balance snapshot should still read back as zero"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_balance(Some(0)) must canonicalize to the missing-entry baseline root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_balance(Some(0)) should deterministically reuse the rewound cached root"
    );
}
#[test]
fn debiting_balance_to_zero_removes_treasury_entry_without_perturbing_restore_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.set_balance("treasury.worker_slashes", 9);
    let funded_root = state.state_root();
    assert_ne!(
        funded_root, baseline_root,
        "sanity: funding a treasury entry must perturb the root"
    );

    state
        .debit_balance("treasury.worker_slashes", 9)
        .expect("debit to zero should succeed");

    assert_eq!(
        state.balance_of("treasury.worker_slashes"),
        0,
        "debiting to zero should read back as zero"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "debiting a treasury balance to zero must remove the entry so state_root returns to the missing-entry baseline"
    );
}
#[test]
fn restore_balance_none_is_slot_scoped_even_with_multiple_treasury_entries() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.set_balance("treasury.challenge_forfeits", 11);
    let only_forfeits_root = state.state_root();

    state.set_balance("treasury.worker_slashes", 17);
    let root_with_both = state.state_root();

    assert_ne!(
        root_with_both, only_forfeits_root,
        "sanity: adding a second treasury entry must perturb state_root"
    );

    state.restore_balance("treasury.challenge_forfeits", None);

    assert_eq!(
        state.balance_of("treasury.challenge_forfeits"),
        0,
        "slot-scoped restore should remove the targeted treasury entry"
    );
    assert_eq!(
        state.balance_of("treasury.worker_slashes"),
        17,
        "slot-scoped restore must preserve unrelated treasury entries"
    );
    assert_ne!(
        state.state_root(),
        empty_root,
        "removing one treasury slot must not collapse state_root to the empty baseline while another treasury entry still exists"
    );

    let mut expected = StateStore::new();
    expected.set_balance("treasury.worker_slashes", 17);
    let only_worker_slashes_root = expected.state_root();

    assert_eq!(
        state.state_root(),
        only_worker_slashes_root,
        "restore_balance(None) should produce the same deterministic root as a canonical state containing only the preserved treasury entry"
    );

    state.restore_balance("treasury.challenge_forfeits", Some(11));
    assert_eq!(
        state.state_root(),
        root_with_both,
        "restoring the removed treasury snapshot must rewind state_root exactly to the prior two-entry root"
    );
}
#[test]
fn explicit_default_monetary_snapshot_has_same_state_root_as_empty_state() {
    let empty = StateStore::new();
    let empty_root = empty.state_root();

    let mut explicit_default = StateStore::new();
    explicit_default.restore_monetary_state(MonetaryState::default());

    assert_eq!(
        explicit_default.state_root(),
        empty_root,
        "state_root must treat an explicit default monetary snapshot the same as the canonical empty monetary state"
    );
    assert_eq!(
        explicit_default.state_root(),
        empty_root,
        "repeated reads after restoring the default monetary snapshot should deterministically reuse the canonical empty root"
    );
}
#[test]
fn restoring_default_monetary_snapshot_rewinds_mixed_state_root_exactly() {
    let mut state = StateStore::new();
    state.set_balance("treasury.challenge_forfeits", 11);
    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1_200,
        }),
    );

    let baseline_root = state.state_root();
    assert_eq!(
        state.monetary_state(),
        &MonetaryState::default(),
        "sanity: baseline mixed state should start from the canonical default monetary snapshot"
    );

    state.restore_monetary_state(MonetaryState {
        last_tick_height: 42,
        tick_count: 3,
        total_minted: 17,
        total_burned: 5,
        net_issuance: 12,
    });
    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "sanity: non-default monetary counters must perturb the root even when pending governance and treasury state are unchanged"
    );

    state.restore_monetary_state(MonetaryState::default());

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the default monetary snapshot must rewind the mixed pending/treasury root exactly"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restoring the default monetary snapshot should deterministically reuse the rewound mixed-state root"
    );
}
#[test]
fn restore_monetary_state_rewinds_state_root_after_zero_net_tick_roundtrip() {
    let mut state = StateStore::new();
    state
        .set_gov_param(
            0,
            1,
            "monetary_policy_tick_interval_blocks".to_string(),
            "10".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            2,
            "monetary_policy_tick_cooldown_blocks".to_string(),
            "1".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            3,
            "monetary_base_issuance_per_tick".to_string(),
            "5".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            4,
            "monetary_base_burn_per_tick".to_string(),
            "5".to_string(),
        )
        .unwrap();

    let baseline_root = state.state_root();
    let monetary_snapshot = state.monetary_state_snapshot();

    let event = state.policy_tick(10).unwrap();
    assert_eq!(
        event.net_delta, 0,
        "sanity: tick should have zero net issuance"
    );
    assert_eq!(
        state.monetary_state().net_issuance,
        monetary_snapshot.net_issuance,
        "sanity: zero-net tick should preserve net issuance even while other counters advance"
    );

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "zero-net monetary ticks must still perturb state_root because gross counters and tick metadata changed"
    );

    state.restore_monetary_state(monetary_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_monetary_state must rewind state_root exactly even after a zero-net issuance tick"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after zero-net monetary restore should deterministically reuse the rewound cached root"
    );
}
#[test]
fn blocked_policy_tick_keeps_monetary_snapshot_and_state_root_stable() {
    let mut state = StateStore::new();
    state
        .set_gov_param(
            0,
            1,
            "monetary_policy_tick_interval_blocks".to_string(),
            "10".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            2,
            "monetary_policy_tick_cooldown_blocks".to_string(),
            "5".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            3,
            "monetary_base_issuance_per_tick".to_string(),
            "7".to_string(),
        )
        .unwrap();
    state
        .set_gov_param(
            0,
            4,
            "monetary_base_burn_per_tick".to_string(),
            "3".to_string(),
        )
        .unwrap();

    let first_event = state
        .policy_tick(10)
        .expect("initial tick should fire at the configured interval");
    assert_eq!(
        first_event.tick_count, 1,
        "sanity: first successful tick should advance tick_count"
    );

    let baseline_snapshot = state.monetary_state_snapshot();
    let baseline_root = state.state_root();
    assert_eq!(
        state.state_root(),
        baseline_root,
        "sanity: repeated reads before the blocked tick should reuse the cached baseline root"
    );

    assert!(
        !state.should_trigger_policy_tick(10),
        "the same block height must not retrigger a policy tick once last_tick_height already matches it"
    );
    assert!(
        !state.should_trigger_policy_tick(14),
        "non-interval heights should fail closed without scheduling a monetary tick"
    );
    assert!(
        state.policy_tick(14).is_none(),
        "blocked non-triggering tick attempts should fail closed without mutating monetary state"
    );

    assert_eq!(
        state.monetary_state_snapshot(),
        baseline_snapshot,
        "blocked policy_tick attempts must preserve the canonical monetary snapshot exactly"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "blocked policy_tick attempts must leave state_root unchanged"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after a blocked policy_tick attempt should deterministically reuse the unchanged cached root"
    );
}
