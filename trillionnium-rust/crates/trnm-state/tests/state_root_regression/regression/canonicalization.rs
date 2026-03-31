use super::*;

#[test]
fn new_tasks_canonicalize_embedded_version_for_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let task = TaskObject {
        task_id: 8_001,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("canonicalize task version".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model-a".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test:alice".into()),
                produced_at: Some("2026-03-14T00:00:00Z".into()),
                provenance_index: Some("prov-task-8001".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(52),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    let mut mismatched_version = task.clone();
    mismatched_version.version = 99;

    let ref_a = state_a.put_task_new(task).unwrap();
    let ref_b = state_b.put_task_new(mismatched_version).unwrap();

    assert_eq!(ref_a.version, 1);
    assert_eq!(ref_b.version, 1);
    assert_eq!(state_a.get_task(8_001).unwrap().version, 1);
    assert_eq!(state_b.get_task(8_001).unwrap().version, 1);
    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should ignore caller-supplied task version noise on initial task insertion"
    );
}
#[test]
fn new_governance_proposals_canonicalize_embedded_version_for_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let proposal = GovProposalObject {
        proposal_id: 9_001,
        title: "Raise challenge bond".into(),
        proposer: "governance.alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let mut mismatched_version = proposal.clone();
    mismatched_version.version = 99;

    let ref_a = state_a.put_proposal_new(proposal).unwrap();
    let ref_b = state_b.put_proposal_new(mismatched_version).unwrap();

    assert_eq!(ref_a.version, 1);
    assert_eq!(ref_b.version, 1);
    assert_eq!(
        state_a.get_proposal(9_001).unwrap().version,
        1,
        "new proposals should canonicalize embedded version to the initial stored object version"
    );
    assert_eq!(
        state_b.get_proposal(9_001).unwrap().version,
        1,
        "caller-supplied proposal version must not perturb the canonical initial stored version"
    );
    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should ignore caller-supplied proposal version noise on initial proposal insertion"
    );
}
#[test]
fn insertion_order_of_applied_gov_params_keeps_state_root_deterministic() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .set_gov_param(0, 7_001, "max_block_ms".into(), "250".into())
        .expect("first applied governance param should succeed");
    state_a
        .set_gov_param(0, 7_002, "max_parallel_workers".into(), "16".into())
        .expect("second applied governance param should succeed");

    state_b
        .set_gov_param(0, 7_002, "max_parallel_workers".into(), "16".into())
        .expect("same applied governance params should succeed in reverse order");
    state_b
        .set_gov_param(0, 7_001, "max_block_ms".into(), "250".into())
        .expect("reverse-order insertion should preserve canonical applied governance state");

    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should be deterministic for equivalent applied governance params and key-index mappings regardless of insertion order"
    );
}
#[test]
fn zero_challenge_escrow_balance_canonicalizes_to_missing_entry_even_with_other_pending_and_monetary_state(
) {
    let mut missing = StateStore::new();
    let mut explicit_zero = StateStore::new();

    for state in [&mut missing, &mut explicit_zero] {
        state.set_balance("treasury.challenge_forfeits", 11);
        state.set_balance("treasury.worker_slashes", 7);
        state.restore_pending_gov_update(
            "challenge_min_bond",
            Some(PendingGovParamUpdate {
                key_id: 302,
                key: "challenge_min_bond".into(),
                value: "175".into(),
                activate_at_height: 260,
            }),
        );
        state.restore_pending_resolve_approval(
            4_200,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "authority.beta".into(),
                authority_set: "authority.alpha,authority.beta".into(),
                task_version: 4,
            }),
        );
        state.restore_monetary_state(MonetaryState {
            last_tick_height: 91,
            tick_count: 5,
            total_minted: 25,
            total_burned: 6,
            net_issuance: 19,
        });
    }

    let missing_root = missing.state_root();
    explicit_zero.set_balance("treasury.challenge_escrow", 0);

    assert_eq!(
        explicit_zero.balance_of("treasury.challenge_escrow"),
        0,
        "sanity: explicit zero challenge escrow balance should still read back as zero"
    );
    assert_eq!(
        explicit_zero.state_root(),
        missing_root,
        "state_root must treat zero challenge escrow balance the same as a missing entry even when other pending, treasury, and monetary state is present"
    );
}

#[test]
fn zero_worker_slashes_balance_canonicalizes_to_missing_entry_even_with_other_pending_and_monetary_state(
) {
    let mut missing = StateStore::new();
    let mut explicit_zero = StateStore::new();

    for state in [&mut missing, &mut explicit_zero] {
        state.set_balance("treasury.challenge_forfeits", 11);
        state.set_balance("treasury.challenge_escrow", 13);
        state.restore_pending_gov_update(
            "challenge_min_bond",
            Some(PendingGovParamUpdate {
                key_id: 303,
                key: "challenge_min_bond".into(),
                value: "175".into(),
                activate_at_height: 261,
            }),
        );
        state.restore_pending_resolve_approval(
            4_201,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority.alpha".into(),
                authority_set: "authority.alpha,authority.beta".into(),
                task_version: 5,
            }),
        );
        state.restore_monetary_state(MonetaryState {
            last_tick_height: 92,
            tick_count: 6,
            total_minted: 29,
            total_burned: 7,
            net_issuance: 22,
        });
    }

    let missing_root = missing.state_root();
    explicit_zero.set_balance("treasury.worker_slashes", 0);

    assert_eq!(
        explicit_zero.balance_of("treasury.worker_slashes"),
        0,
        "sanity: explicit zero worker slashes balance should still read back as zero"
    );
    assert_eq!(
        explicit_zero.state_root(),
        missing_root,
        "state_root must treat zero worker slashes balance the same as a missing entry even when other pending, collateral, and monetary state is present"
    );
}
#[test]
fn insertion_order_of_balances_pending_and_monetary_snapshots_keeps_state_root_deterministic() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.set_balance("treasury.challenge_forfeits", 11);
    state_a.set_balance("treasury.worker_slashes", 7);
    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 301,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 250,
        }),
    );
    state_a.restore_pending_resolve_approval(
        4_200,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 90,
        tick_count: 4,
        total_minted: 21,
        total_burned: 5,
        net_issuance: 16,
    });

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 90,
        tick_count: 4,
        total_minted: 21,
        total_burned: 5,
        net_issuance: 16,
    });
    state_b.restore_pending_resolve_approval(
        4_200,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 301,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 250,
        }),
    );
    state_b.set_balance("treasury.worker_slashes", 7);
    state_b.set_balance("treasury.challenge_forfeits", 11);

    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should be deterministic for equivalent pending/treasury/monetary state regardless of mutation order"
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
fn insertion_order_of_pending_gov_updates_keeps_state_root_deterministic() {
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
    state_a.restore_pending_gov_update(
        "min_worker_stake",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "min_worker_stake".to_string(),
            value: "9000".to_string(),
            activate_at_height: 1_040,
        }),
    );

    state_b.restore_pending_gov_update(
        "min_worker_stake",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "min_worker_stake".to_string(),
            value: "9000".to_string(),
            activate_at_height: 1_040,
        }),
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
        state_a.state_root(),
        state_b.state_root(),
        "state_root should be deterministic for equivalent pending governance queues regardless of restore/insertion order"
    );
}

#[test]
fn checkpoint_audit_summary_rejects_noncanonical_prev_hash_surface() {
    let checkpoint = CheckpointMeta {
        height: 2,
        state_root_hex: "ab".repeat(32),
        wal_entry_hash_hex: "cd".repeat(32),
    };
    let canonical_wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: checkpoint.state_root_hex.clone(),
        prev_hash_hex: Some("01".repeat(32)),
    };
    let canonical_checkpoint = CheckpointMeta {
        wal_entry_hash_hex: canonical_wal.content_hash_hex(),
        ..checkpoint.clone()
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&canonical_checkpoint, &canonical_wal),
        "sanity: canonical checkpoint/WAL evidence should remain audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&canonical_checkpoint, &canonical_wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should emit an audit summary"
    );

    let mut drifted_wal = canonical_wal.clone();
    drifted_wal.prev_hash_hex = Some("01".repeat(32).to_uppercase());

    assert!(
        !checkpoint_evidence_surface_is_canonical(&canonical_checkpoint, &drifted_wal),
        "checkpoint audit surfaces must reject uppercase prev_hash_hex drift so non-genesis WAL linkage stays byte-canonical"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&canonical_checkpoint, &drifted_wal).is_none(),
        "audit summaries must fail closed when WAL predecessor linkage is not canonical lower hex"
    );
}
