use trnm_state::*;
use trnm_types::*;

#[test]
fn task_metadata_and_proof_type_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 7,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };

    st1.put_task_new(base_task.clone()).unwrap();

    let mut changed_task = base_task;
    changed_task.proof_type = ProofType::Zk;
    changed_task.metadata = Some(TaskMetadata {
        note: Some("zk task".into()),
        task_type: Some("inference".into()),
        input_hash: Some("ab".repeat(32)),
        model: Some(TaskModelMetadata {
            model_id: Some("trnm-model".into()),
            model_digest: Some("cd".repeat(32)),
            version: Some("v1".into()),
        }),
        provenance: Some(TaskProvenanceMetadata {
            producer_did: Some("did:trnm:test".into()),
            produced_at: Some("2026-03-11T08:42:00Z".into()),
            provenance_index: Some("prov-7".into()),
            privacy_tier: Some(PrivacyTier::Internal),
        }),
    });
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task proof_type and metadata"
    );
}

#[test]
fn pending_sensitive_gov_updates_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let st2 = StateStore::new();

    // Base states are identical
    assert_eq!(st1.state_root(), st2.state_root());

    // Add a timelocked sensitive pending update to st1 only.
    let outcome = st1
        .set_gov_param(
            1000,
            7001,
            "challenge_min_bond".to_string(),
            "5000".to_string(),
        )
        .unwrap();
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    // Roots should now differ because pending_gov_updates contributes to state_root.
    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate pending sensitive governance updates"
    );
}

#[test]
fn treasury_balances_and_monetary_counters_should_affect_state_root_even_when_net_issuance_matches() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    for st in [&mut st1, &mut st2] {
        st.set_gov_param(0, 1, "monetary_policy_tick_interval_blocks".to_string(), "10".to_string())
            .unwrap();
        st.set_gov_param(0, 2, "monetary_policy_tick_cooldown_blocks".to_string(), "1".to_string())
            .unwrap();
    }

    st1.set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "7".to_string())
        .unwrap();
    st1.set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "5".to_string())
        .unwrap();
    st2.set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "9".to_string())
        .unwrap();
    st2.set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "7".to_string())
        .unwrap();

    let e1 = st1.policy_tick(10).unwrap();
    let e2 = st2.policy_tick(10).unwrap();
    assert_eq!(e1.net_delta, e2.net_delta, "sanity: net issuance matches");
    assert_ne!(
        e1.total_minted, e2.total_minted,
        "sanity: gross minted amount differs"
    );
    assert_ne!(
        e1.total_burned, e2.total_burned,
        "sanity: gross burned amount differs"
    );

    st1.set_balance("treasury.challenge_forfeits", 11);
    st2.set_balance("treasury.worker_slashes", 11);

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root must include treasury balance placement and full monetary counters, not only net issuance"
    );
}

#[test]
fn restoring_pending_and_monetary_state_rewinds_state_root_symmetrically() {
    let mut baseline = StateStore::new();
    baseline
        .set_gov_param(
            0,
            1,
            "monetary_policy_tick_interval_blocks".to_string(),
            "10".to_string(),
        )
        .unwrap();
    baseline
        .set_gov_param(
            0,
            2,
            "monetary_policy_tick_cooldown_blocks".to_string(),
            "1".to_string(),
        )
        .unwrap();
    baseline
        .set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "7".to_string())
        .unwrap();
    baseline
        .set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "5".to_string())
        .unwrap();
    baseline.policy_tick(10).unwrap();
    baseline.set_balance("treasury.challenge_forfeits", 11);

    let root_before = baseline.state_root();
    let snapshot = baseline.clone();

    baseline
        .set_gov_param(1000, 7001, "max_block_ms".to_string(), "5000".to_string())
        .unwrap();
    baseline
        .stage_or_confirm_resolve_approval(42, 1, true, "resolver-a", "resolver-a,resolver-b")
        .unwrap();
    baseline.set_balance("treasury.worker_slashes", 23);
    baseline.policy_tick(20).unwrap();

    let root_after_mutation = baseline.state_root();
    assert_ne!(
        root_before, root_after_mutation,
        "sanity: pending/treasury/monetary mutations must change the state root"
    );

    let restored = snapshot.state_root();
    assert_eq!(
        root_before, restored,
        "cloned snapshot root should remain stable before explicit restore"
    );

    baseline = snapshot;

    assert_eq!(
        baseline.state_root(),
        root_before,
        "restoring the pre-mutation snapshot must rewind state_root exactly"
    );
}

#[test]
fn explicit_restore_apis_rewind_state_root_after_task_balance_and_pending_resolve_mutation() {
    let mut state = StateStore::new();
    let task = TaskObject {
        task_id: 9,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };

    let task_ref = state.put_task_new(task.clone()).unwrap();
    state.set_balance("treasury.worker_slashes", 3);

    let task_snapshot = state.get_task(task_ref.id);
    let balance_snapshot = Some(state.balance_of("treasury.worker_slashes"));
    let pending_snapshot = state.pending_resolve_approval_snapshot(task.task_id);
    let root_before = state.state_root();

    let mut changed_task = state.get_task(task_ref.id).unwrap();
    changed_task.status = TaskStatus::Challenged;
    changed_task.challenger = Some("bob".into());
    changed_task.challenge_bond = Some(17);
    state.update_task(task_ref, changed_task).unwrap();
    state.set_balance("treasury.worker_slashes", 44);
    state
        .stage_or_confirm_resolve_approval(9, 2, true, "resolver-a", "resolver-a,resolver-b")
        .unwrap();

    let root_after_mutation = state.state_root();
    assert_ne!(
        root_before, root_after_mutation,
        "sanity: explicit task/balance/pending mutations must perturb the state root"
    );

    state.restore_task(9, task_snapshot);
    state.restore_balance("treasury.worker_slashes", balance_snapshot);
    state.restore_pending_resolve_approval(9, pending_snapshot);

    assert_eq!(
        state.state_root(),
        root_before,
        "explicit restore APIs must rewind state_root exactly to the pre-mutation root"
    );
}

#[test]
fn restore_roundtrip_stays_deterministic_even_after_cached_state_root_reads() {
    let mut state = StateStore::new();
    let task = TaskObject {
        task_id: 10,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };

    let task_ref = state.put_task_new(task.clone()).unwrap();
    state.set_balance("treasury.challenge_forfeits", 11);
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
        .set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "7".to_string())
        .unwrap();
    state
        .set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "5".to_string())
        .unwrap();
    state.policy_tick(10).unwrap();

    let task_snapshot = state.get_task(task_ref.id);
    let balance_snapshot = Some(state.balance_of("treasury.challenge_forfeits"));
    let pending_snapshot = state.pending_resolve_approval_snapshot(task.task_id);
    let monetary_snapshot = state.monetary_state_snapshot();
    let baseline_root = state.state_root();
    assert_eq!(
        state.state_root(),
        baseline_root,
        "sanity: repeated reads should hit the cached baseline root deterministically"
    );

    let mut changed_task = state.get_task(task_ref.id).unwrap();
    changed_task.status = TaskStatus::Challenged;
    changed_task.challenger = Some("bob".into());
    changed_task.challenge_bond = Some(17);
    state.update_task(task_ref, changed_task).unwrap();
    state.set_balance("treasury.challenge_forfeits", 19);
    state
        .stage_or_confirm_resolve_approval(10, 2, true, "resolver-a", "resolver-a,resolver-b")
        .unwrap();
    state.policy_tick(20).unwrap();

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "sanity: task/balance/pending/monetary mutations must perturb the cached state root"
    );
    assert_eq!(
        state.state_root(),
        mutated_root,
        "sanity: repeated reads should hit the cached mutated root deterministically"
    );

    state.restore_task(10, task_snapshot);
    state.restore_balance("treasury.challenge_forfeits", balance_snapshot);
    state.restore_pending_resolve_approval(10, pending_snapshot);
    state.restore_monetary_state(monetary_snapshot);
    state = state.clone();

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore path must invalidate caches so cloned/restored state returns to the exact baseline root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "post-restore repeated reads should deterministically reuse the rewound cached root"
    );
}

#[test]
fn idempotent_non_sensitive_gov_reapply_keeps_state_root_stable() {
    let mut state = StateStore::new();
    state
        .set_gov_param(77_700, 7_401, "max_block_ms".into(), "15".into())
        .expect("initial non-sensitive apply should succeed");

    let baseline_root = state.state_root();

    state
        .set_gov_param(77_701, 7_401, "max_block_ms".into(), "15".into())
        .expect("idempotent reapply should succeed");

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "non-sensitive idempotent reapply should not leave pending state behind"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "idempotent non-sensitive governance reapply must not perturb the deterministic state root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after idempotent governance reapply should stay on the same cached root"
    );
}

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
fn restore_pending_none_rewinds_state_root_after_removing_staged_resolve_approval() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(88, 4, true, "resolver-a", "resolver-a,resolver-b")
        .expect("staging resolve approval should succeed");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged resolve approval must perturb the state root"
    );

    state.restore_pending_resolve_approval(88, None);

    assert!(
        state.pending_resolve_approval(88).is_none(),
        "restoring a missing pending snapshot should remove the staged resolve approval"
    );
    assert_eq!(
        state.pending_resolve_first_approver(88),
        None,
        "restoring a missing pending snapshot should also clear cached approver metadata"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_pending_resolve_approval(None) must rewind state_root exactly after deleting a staged approval"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_pending_resolve_approval(None) should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_gov_update_none_rewinds_state_root_after_removing_timelocked_update() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    let outcome = state
        .set_gov_param(
            1_000,
            7_001,
            "challenge_min_bond".to_string(),
            "5000".to_string(),
        )
        .expect("staging a sensitive governance update should succeed");
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: a staged governance update must perturb the state root"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "sanity: the pending governance update should be visible before restore"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restoring a missing governance snapshot should remove the staged update"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "restore_gov_param_update(None) must rewind state_root exactly after deleting a staged governance update"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restore_gov_param_update(None) should deterministically reuse the rewound cached root"
    );
}

#[test]
fn zero_balance_and_missing_balance_have_identical_state_root() {
    let missing = StateStore::new();
    let missing_root = missing.state_root();

    let mut explicit_zero = StateStore::new();
    explicit_zero.set_balance("treasury.challenge_forfeits", 0);

    assert_eq!(
        explicit_zero.balance_of("treasury.challenge_forfeits"),
        0,
        "sanity: explicit zero balance should still read back as zero"
    );
    assert_eq!(
        explicit_zero.state_root(),
        missing_root,
        "state root must treat explicit zero treasury balances the same as missing entries"
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
        .set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "5".to_string())
        .unwrap();
    state
        .set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "5".to_string())
        .unwrap();

    let baseline_root = state.state_root();
    let monetary_snapshot = state.monetary_state_snapshot();

    let event = state.policy_tick(10).unwrap();
    assert_eq!(event.net_delta, 0, "sanity: tick should have zero net issuance");
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
fn restore_combined_pending_and_monetary_none_roundtrip_rewinds_state_root() {
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
        .set_gov_param(0, 3, "monetary_base_issuance_per_tick".to_string(), "7".to_string())
        .unwrap();
    state
        .set_gov_param(0, 4, "monetary_base_burn_per_tick".to_string(), "5".to_string())
        .unwrap();

    let baseline_root = state.state_root();
    let baseline_monetary = state.monetary_state_snapshot();
    let baseline_pending = state.pending_gov_update("challenge_min_bond");

    let outcome = state
        .set_gov_param(
            1_000,
            7_001,
            "challenge_min_bond".to_string(),
            "5000".to_string(),
        )
        .expect("staging a sensitive governance update should succeed");
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));
    state.policy_tick(10).expect("policy tick should succeed");

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "sanity: combined pending governance and monetary mutations must perturb the root"
    );

    state.restore_pending_gov_update("challenge_min_bond", baseline_pending);
    state.restore_monetary_state(baseline_monetary);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring both pending governance and monetary snapshots must rewind state_root exactly"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "post-restore repeated reads should deterministically reuse the exact rewound root"
    );
}
