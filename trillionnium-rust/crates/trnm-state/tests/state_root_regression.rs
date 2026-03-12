use trnm_state::*;
use trnm_types::*;

#[test]
fn task_metadata_string_field_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let task1 = TaskObject {
        task_id: 6,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("ab".into()),
            task_type: Some("c".into()),
            input_hash: None,
            model: None,
            provenance: None,
        }),
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
    let mut task2 = task1.clone();
    task2.metadata = Some(TaskMetadata {
        note: Some("a".into()),
        task_type: Some("bc".into()),
        input_hash: None,
        model: None,
        provenance: None,
    });

    st1.put_task_new(task1).unwrap();
    st2.put_task_new(task2).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should frame task metadata string lengths so distinct field boundaries cannot collide"
    );
}

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
fn task_challenge_window_snapshot_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Revealed,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(42),
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenge_window_blocks_snapshot = Some(24);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task challenge_window_blocks_snapshot so reveal-time resolve semantics remain deterministic"
    );
}

#[test]
fn task_provenance_privacy_tier_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_001,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("privacy-sensitive task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test".into()),
                produced_at: Some("2026-03-12T06:45:00Z".into()),
                provenance_index: Some("prov-privacy-1".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
        }),
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

    let mut changed_task = base_task.clone();
    changed_task.metadata.as_mut().unwrap().provenance.as_mut().unwrap().privacy_tier =
        Some(PrivacyTier::Restricted);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task provenance privacy_tier so otherwise identical privacy classifications cannot hash identically"
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
fn embedded_pending_gov_update_key_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    st1.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );
    st2.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "min_worker_stake".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate embedded pending governance key names so mismatched restore snapshots cannot hash identically"
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
fn pending_resolve_slash_worker_flag_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve slash_worker must contribute to state_root so slash-vs-refund intent cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original slash_worker flag should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_confirmations_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 2,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve confirmations must contribute to state_root so pre-quorum and quorum-ready stages cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original confirmation count should rewind the deterministic root exactly"
    );
}

#[test]
fn restore_pending_resolve_snapshot_with_same_counts_but_different_authority_metadata_rewinds_state_root() {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5150, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5150);
    assert!(baseline_snapshot.is_some(), "sanity: snapshot should capture staged approval");

    state.restore_pending_resolve_approval(
        5150,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-b".into(),
            authority_set: "resolver-a,resolver-c".into(),
            task_version: 7,
        }),
    );

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "changing only pending resolve authority metadata must perturb state_root"
    );

    state.restore_pending_resolve_approval(5150, baseline_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the original pending resolve snapshot must rewind state_root exactly even when only authority metadata changed"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restoring pending resolve authority metadata should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_resolve_snapshot_with_same_authority_metadata_but_different_task_version_rewinds_state_root() {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5_151, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5_151);
    assert!(baseline_snapshot.is_some(), "sanity: snapshot should capture staged approval");

    state.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 8,
        }),
    );

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "changing only pending resolve task_version must perturb state_root"
    );

    state.restore_pending_resolve_approval(5_151, baseline_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the original pending resolve snapshot must rewind state_root exactly even when only task_version changed"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after restoring pending resolve task_version should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_resolve_none_on_mismatched_slot_keeps_canonical_pending_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(5_200, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let snapshot = state
        .pending_resolve_approval_snapshot(5_200)
        .expect("sanity: canonical pending resolve snapshot should exist");
    let canonical_pending_root = state.state_root();
    assert_ne!(
        canonical_pending_root, baseline_root,
        "sanity: staged pending resolve approval must perturb the root"
    );

    state.restore_pending_resolve_approval(5_201, Some(snapshot.clone()));
    assert!(
        state.pending_resolve_approval_snapshot(5_201).is_some(),
        "restoring a pending resolve snapshot through another task slot should materialize a distinct staged entry for that slot"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_200).is_some(),
        "mismatched-slot restore must preserve the canonical pending task slot"
    );
    assert_ne!(
        state.state_root(),
        canonical_pending_root,
        "adding the same pending resolve snapshot under a second task slot must perturb the root because the task_id slot is part of state identity"
    );

    state.restore_pending_resolve_approval(5_201, None);
    assert!(
        state.pending_resolve_approval_snapshot(5_200).is_some(),
        "clearing a mismatched pending resolve slot with None must not delete the canonical staged task slot"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "clearing the extra mismatched pending resolve slot must return to the canonical pending root"
    );

    state.restore_pending_resolve_approval(5_200, None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the canonical pending resolve slot must return the state root to baseline"
    );
}

#[test]
fn restore_pending_resolve_none_is_slot_scoped_even_with_multiple_pending_entries() {
    let mut state = StateStore::new();

    state.restore_pending_resolve_approval(
        5_210,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state.restore_pending_resolve_approval(
        5_211,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-c".into(),
            authority_set: "resolver-c,resolver-d".into(),
            task_version: 9,
        }),
    );

    let root_with_both = state.state_root();
    assert!(state.pending_resolve_approval_snapshot(5_210).is_some());
    assert!(state.pending_resolve_approval_snapshot(5_211).is_some());

    state.restore_pending_resolve_approval(5_210, None);

    assert!(
        state.pending_resolve_approval_snapshot(5_210).is_none(),
        "slot-scoped restore should remove the targeted pending resolve entry"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_211).is_some(),
        "slot-scoped restore must preserve unrelated pending resolve entries"
    );
    assert_ne!(
        state.state_root(),
        root_with_both,
        "removing only one pending resolve entry should perturb the root while preserving unrelated pending resolve state"
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
fn crediting_zero_to_missing_balance_keeps_state_root_on_missing_entry_baseline() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .credit_balance("treasury.challenge_forfeits", 0)
        .expect("crediting zero should succeed");

    assert_eq!(
        state.balance_of("treasury.challenge_forfeits"),
        0,
        "crediting zero should still read back as zero"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "crediting zero to a missing treasury entry must not materialize a zero-balance row or perturb state_root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after zero-credit should deterministically reuse the missing-entry baseline root"
    );
}

#[test]
fn monetary_tick_metadata_should_affect_state_root_even_when_issuance_totals_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 1,
        total_minted: 5,
        total_burned: 5,
        net_issuance: 0,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 20,
        tick_count: 2,
        total_minted: 5,
        total_burned: 5,
        net_issuance: 0,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include monetary tick metadata, not only issuance totals or net issuance"
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

#[test]
fn restore_pending_gov_update_uses_snapshot_key_identity_for_state_root_roundtrip() {
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

    let baseline_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: pending snapshot should exist");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged governance update must perturb the root"
    );

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: baseline_snapshot.key_id,
            key: baseline_snapshot.key.clone(),
            value: baseline_snapshot.value.clone(),
            activate_at_height: baseline_snapshot.activate_at_height,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "restore should not materialize a pending update under a mismatched key slot"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "restore should preserve the original logical pending key"
    );
    assert_eq!(
        state.state_root(),
        pending_root,
        "restoring an identical pending snapshot through a mismatched caller key should preserve the same deterministic root"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "removing the pending update after the mismatched-key restore roundtrip must return to the original baseline root"
    );
}

#[test]
fn restore_pending_gov_update_none_on_mismatched_slot_keeps_canonical_pending_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    let outcome = state
        .set_gov_param(
            1_000,
            7_011,
            "challenge_min_bond".to_string(),
            "6100".to_string(),
        )
        .expect("sensitive governance update should stage successfully");
    assert!(matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }));

    let snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: canonical pending snapshot should exist");
    let canonical_pending_root = state.state_root();
    assert_ne!(
        canonical_pending_root, baseline_root,
        "sanity: staged pending governance update must perturb the root"
    );

    state.restore_pending_gov_update("max_block_ms", Some(snapshot.clone()));
    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched-slot restore must not materialize a stale caller-key entry"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "mismatched-slot restore must preserve the canonical pending key"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "replaying the same snapshot through a mismatched slot must preserve the canonical pending root"
    );

    state.restore_pending_gov_update("max_block_ms", None);
    assert!(
        state.pending_gov_update("challenge_min_bond").is_some(),
        "clearing a mismatched slot with None must not delete the canonical pending key"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "clearing a mismatched slot with None must preserve the canonical pending root"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the canonical pending key must return the state root to baseline"
    );
}

#[test]
fn restore_pending_gov_update_none_is_slot_scoped_even_with_multiple_pending_entries() {
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_011,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state.restore_pending_gov_update(
        "challenge_success_bounty",
        Some(PendingGovParamUpdate {
            key_id: 7_012,
            key: "challenge_success_bounty".to_string(),
            value: "12".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_with_both = state.state_root();
    assert!(state.pending_gov_update("challenge_min_bond").is_some());
    assert!(state.pending_gov_update("challenge_success_bounty").is_some());

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "slot-scoped restore should remove the targeted pending key"
    );
    assert!(
        state.pending_gov_update("challenge_success_bounty").is_some(),
        "slot-scoped restore must preserve unrelated pending keys"
    );
    assert_ne!(
        state.state_root(),
        root_with_both,
        "removing only one pending key should perturb the root while preserving unrelated pending state"
    );
}

#[test]
fn restore_pending_gov_update_mismatched_slot_clears_stale_entry_and_preserves_snapshot_identity() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .set_gov_param(0, 111, "max_block_ms".to_string(), "500".to_string())
        .expect("non-sensitive baseline update should apply");
    let challenge_outcome = state
        .set_gov_param(
            1_000,
            7_002,
            "challenge_min_bond".to_string(),
            "6000".to_string(),
        )
        .expect("sensitive governance update should stage successfully");
    assert!(matches!(challenge_outcome, GovParamUpdateOutcome::Scheduled { .. }));

    let challenge_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("sanity: pending challenge snapshot should exist");
    let challenge_root = state.state_root();
    assert_ne!(
        challenge_root, baseline_root,
        "sanity: pending challenge update must perturb the root"
    );

    state
        .set_gov_param(0, 111, "max_block_ms".to_string(), "650".to_string())
        .expect("updating a non-sensitive key should succeed");
    let root_before_restore = state.state_root();
    assert_ne!(
        root_before_restore, challenge_root,
        "sanity: mutating the mismatched caller slot should perturb the root before restore"
    );

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: challenge_snapshot.key_id,
            key: challenge_snapshot.key.clone(),
            value: challenge_snapshot.value.clone(),
            activate_at_height: challenge_snapshot.activate_at_height,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "restore through a mismatched slot must scrub any stale entry under the caller key"
    );
    let restored_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("challenge snapshot should remain addressable by its own key");
    assert_eq!(
        restored_snapshot.key, challenge_snapshot.key,
        "restore should preserve snapshot key identity"
    );
    assert_eq!(
        restored_snapshot.key_id, challenge_snapshot.key_id,
        "restore should preserve the staged governance key id"
    );
    assert_eq!(
        restored_snapshot.value, challenge_snapshot.value,
        "restore should preserve the staged governance value"
    );
    assert_eq!(
        restored_snapshot.activate_at_height, challenge_snapshot.activate_at_height,
        "restore should preserve the staged activation height"
    );
    assert_eq!(
        state.state_root(),
        root_before_restore,
        "re-inserting the identical logical snapshot while the caller slot is already non-pending should leave the deterministic root unchanged"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);
    state.restore_task(111, None);
    assert_eq!(
        state.state_root(),
        baseline_root,
        "clearing the preserved pending snapshot and reverting the helper mutation must return to the original baseline root"
    );
}

#[test]
fn pending_gov_update_key_id_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance key_id must contribute to state_root so logically distinct staged updates do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance key_id should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_activation_height_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_021,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance activation height must contribute to state_root so distinct timelock schedules do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance activation height should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_value_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6500".to_string(),
            activate_at_height: 1_020,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance value must contribute to state_root so distinct staged monetary/security settings do not hash the same"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance value should rewind the deterministic root exactly"
    );
}
