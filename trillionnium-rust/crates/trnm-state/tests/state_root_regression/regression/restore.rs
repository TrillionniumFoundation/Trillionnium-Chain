use super::*;

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
        .set_gov_param(
            0,
            3,
            "monetary_base_issuance_per_tick".to_string(),
            "7".to_string(),
        )
        .unwrap();
    baseline
        .set_gov_param(
            0,
            4,
            "monetary_base_burn_per_tick".to_string(),
            "5".to_string(),
        )
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
            "5".to_string(),
        )
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
            "5".to_string(),
        )
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

#[test]
fn restore_task_on_non_task_slot_scrubs_foreign_object_and_rewinds_state_root() {
    let empty_root = StateStore::new().state_root();

    let mut state = StateStore::new();
    state
        .set_gov_param(0, 9, "max_block_ms".to_string(), "5000".to_string())
        .expect("sanity: should be able to seed a governance object at the target slot");

    let foreign_root = state.state_root();
    assert_ne!(
        foreign_root, empty_root,
        "sanity: occupying the slot with a foreign object must perturb the empty root"
    );

    state.restore_task(
        9,
        Some(TaskObject {
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
        }),
    );

    assert!(
        state.get_task(9).is_none(),
        "restore_task must fail closed instead of materializing a task over a non-task slot"
    );
    assert!(
        state.get_ref(9).is_none(),
        "restore_task must scrub the foreign object slot rather than leave an ambiguous object/version binding"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "scrubbing the foreign slot must rewind state_root exactly to the canonical empty baseline"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "post-scrub repeated reads should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_task_zero_version_on_foreign_slot_preserves_existing_owner_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(0, 17, "max_block_ms".to_string(), "5000".to_string())
        .expect("sanity: should be able to seed a governance object at the target slot");

    let foreign_object = state.get_param(17).expect("foreign object must exist");
    let foreign_root = state.state_root();

    state.restore_task(
        17,
        Some(TaskObject {
            task_id: 17,
            creator: "alice".into(),
            bounty: 10,
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
            version: 0,
        }),
    );

    assert!(
        state.get_task(17).is_none(),
        "invalid restore payloads must not materialize a task over an occupied foreign slot"
    );
    assert_eq!(
        state.get_param(17),
        Some(foreign_object),
        "foreign object ownership must dominate malformed task restore payloads"
    );
    assert_eq!(
        state.state_root(),
        foreign_root,
        "malformed task restore against a foreign slot must preserve the canonical root"
    );
}
