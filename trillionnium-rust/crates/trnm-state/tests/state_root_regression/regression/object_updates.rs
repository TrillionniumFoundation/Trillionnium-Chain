use super::*;

#[test]
fn restore_task_snapshot_rewinds_state_root_after_proof_and_metadata_mutation() {
    let mut state = StateStore::new();
    let task = TaskObject {
        task_id: 10_101,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("initial task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model-a".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test:alice".into()),
                produced_at: Some("2026-03-12T08:00:00Z".into()),
                provenance_index: Some("prov-task-10101".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: None,
        resolve_deadline_height: Some(52),
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 3,
    };

    let task_ref = state
        .put_task_new(task)
        .expect("task insert should succeed");
    let task_id = task_ref.id;
    let task_snapshot = state.get_task(task_id);
    let baseline_root = state.state_root();

    let mut changed_task = state.get_task(task_ref.id).expect("task should exist");
    changed_task.proof_type = ProofType::Zk;
    changed_task.challenge_window_blocks_snapshot = Some(24);
    changed_task.metadata = Some(TaskMetadata {
        note: Some("mutated task".into()),
        task_type: Some("verification".into()),
        input_hash: Some("ef".repeat(32)),
        model: Some(TaskModelMetadata {
            model_id: Some("trnm-model-b".into()),
            model_digest: Some("12".repeat(32)),
            version: Some("v2".into()),
        }),
        provenance: Some(TaskProvenanceMetadata {
            producer_did: Some("did:trnm:test:bob".into()),
            produced_at: Some("2026-03-12T09:15:00Z".into()),
            provenance_index: Some("prov-task-10101-mutated".into()),
            privacy_tier: Some(PrivacyTier::Restricted),
        }),
        metering: None,
    });
    state
        .update_task(task_ref, changed_task)
        .expect("task mutation should succeed");

    let mutated_root = state.state_root();
    assert_ne!(
        mutated_root, baseline_root,
        "sanity: proof type and nested metadata mutations must perturb state_root"
    );

    state.restore_task(task_id, task_snapshot);

    assert_eq!(
        state.state_root(),
        baseline_root,
        "restoring the original task snapshot must rewind state_root exactly after proof/metadata mutations"
    );
}
#[test]
fn restore_task_mismatched_slot_fails_closed_and_keeps_canonical_task_root() {
    let mut state = StateStore::new();
    let task = TaskObject {
        task_id: 10_202,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("canonical task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model-a".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test:alice".into()),
                produced_at: Some("2026-03-12T10:00:00Z".into()),
                provenance_index: Some("prov-task-10202".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x21; 32]),
        result_hash: Some([0x34; 32]),
        reveal_salt: Some([0x55; 32]),
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(28),
        resolve_deadline_height: Some(52),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 3,
    };

    let task_ref = state
        .put_task_new(task)
        .expect("task insert should succeed");
    let canonical_root = state.state_root();
    let snapshot = state
        .get_task(task_ref.id)
        .expect("canonical task snapshot should exist");

    state.restore_task(task_ref.id + 1, Some(snapshot.clone()));
    assert!(
        state.get_task(task_ref.id + 1).is_none(),
        "restore_task should fail closed when a snapshot's embedded task_id does not match the requested slot"
    );
    assert!(
        state.get_task(task_ref.id).is_some(),
        "failing closed on a mismatched slot must preserve the canonical task slot"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "restore_task should keep the canonical deterministic root when asked to restore a snapshot through a mismatched object slot"
    );

    state.restore_task(task_ref.id + 1, None);

    assert!(
        state.get_task(task_ref.id).is_some(),
        "clearing a mismatched task slot with None must preserve the canonical task slot"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "clearing the extra mismatched task slot must return to the canonical deterministic task root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after clearing the mismatched task slot should deterministically reuse the canonical cached root"
    );
}

#[test]
fn restore_task_rejects_cross_type_slot_takeover_and_preserves_canonical_root() {
    let mut state = StateStore::new();
    let proposal = GovProposalObject {
        proposal_id: 10_350,
        title: "retain canonical proposal owner".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    state
        .put_proposal_new(proposal.clone())
        .expect("canonical governance proposal should be inserted first");
    let root_before = state.state_root();

    state.restore_task(
        proposal.proposal_id,
        Some(TaskObject {
            task_id: proposal.proposal_id,
            creator: "bob".into(),
            bounty: 77,
            status: TaskStatus::Open,
            proof_type: Default::default(),
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
        state.get_task(proposal.proposal_id).is_none(),
        "cross-type task restore must fail closed instead of materializing a task into an existing non-task object slot"
    );
    assert_eq!(
        state.get_proposal(proposal.proposal_id),
        Some(proposal),
        "cross-type task restore must preserve the canonical proposal that already owns the object id"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "cross-type task restore rejection must preserve the canonical deterministic root"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting a cross-type task restore must deterministically reuse the preserved cached root"
    );
}

#[test]
fn cross_type_task_restore_scrubs_stale_pending_resolve_and_rewinds_to_canonical_non_task_root() {
    let mut state = StateStore::new();
    let proposal = GovProposalObject {
        proposal_id: 10_301,
        title: "governance owner".into(),
        description: "canonical non-task occupant".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    state
        .put_proposal_new(proposal.clone())
        .expect("canonical governance proposal should occupy the slot first");
    state
        .restore_pending_resolve_approval(
            proposal.proposal_id,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "resolver-a".into(),
                authority_set: "resolver-a,resolver-b".into(),
                task_version: 1,
            }),
        );
    let root_with_stale_pending = state.state_root();

    state.restore_task(
        proposal.proposal_id,
        Some(TaskObject {
            task_id: proposal.proposal_id,
            creator: "bob".into(),
            bounty: 77,
            status: TaskStatus::Open,
            proof_type: Default::default(),
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
        state.pending_resolve_approval(proposal.proposal_id).is_none(),
        "cross-type task restore rejection should scrub stale task-only residue from a non-task slot"
    );
    assert_eq!(
        state.get_proposal(proposal.proposal_id),
        Some(proposal),
        "cross-type task restore rejection must preserve the canonical non-task occupant"
    );
    assert_ne!(
        state.state_root(),
        root_with_stale_pending,
        "scrubbing stale pending resolve residue should perturb the stale mixed root"
    );
    let canonical_root = state.state_root();
    assert_eq!(
        canonical_root,
        state.state_root(),
        "repeated reads after cross-type stale-residue scrubbing must deterministically reuse the canonical rewound root"
    );
}

#[test]
fn restore_task_none_clears_task_slot_and_rewinds_root() {
    let mut state = StateStore::new();
    let task = TaskObject {
        task_id: 10_400,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: Default::default(),
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

    let empty_root = state.state_root();
    state.restore_task(task.task_id, Some(task.clone()));
    let populated_root = state.state_root();
    assert_ne!(
        populated_root, empty_root,
        "restoring a task into an empty store should perturb the deterministic root"
    );
    assert_eq!(state.get_task(task.task_id), Some(task));

    state.restore_task(10_400, None);

    assert!(
        state.get_task(10_400).is_none(),
        "restore_task(None) must clear the canonical task object slot during replay/rollback"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "clearing the restored task slot must rewind the deterministic root exactly"
    );
}

#[test]
fn restore_zero_id_task_snapshot_fails_closed_without_perturbing_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_task(
        0,
        Some(TaskObject {
            task_id: 0,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("invalid zero-id replay snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: Some(TaskModelMetadata {
                    model_id: Some("trnm-model-a".into()),
                    model_digest: Some("cd".repeat(32)),
                    version: Some("v1".into()),
                }),
                provenance: Some(TaskProvenanceMetadata {
                    producer_did: Some("did:trnm:test:alice".into()),
                    produced_at: Some("2026-03-12T10:25:00Z".into()),
                    provenance_index: Some("prov-task-zero-id".into()),
                    privacy_tier: Some(PrivacyTier::Internal),
                }),
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x30; 32]),
            result_hash: Some([0x40; 32]),
            reveal_salt: Some([0x50; 32]),
            committed_at_height: Some(20),
            reveal_deadline_height: Some(30),
            challenge_deadline_height: Some(40),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(28),
            resolve_deadline_height: Some(52),
            challenge_bond: Some(17),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 1,
        }),
    );

    assert!(
        state.get_task(0).is_none(),
        "zero-id restore snapshots must fail closed instead of materializing a task object"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-id restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-id restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_zero_version_task_snapshot_fails_closed_without_perturbing_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_task(
        10_303,
        Some(TaskObject {
            task_id: 10_303,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("invalid replay snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: Some(TaskModelMetadata {
                    model_id: Some("trnm-model-a".into()),
                    model_digest: Some("cd".repeat(32)),
                    version: Some("v1".into()),
                }),
                provenance: Some(TaskProvenanceMetadata {
                    producer_did: Some("did:trnm:test:alice".into()),
                    produced_at: Some("2026-03-12T10:30:00Z".into()),
                    provenance_index: Some("prov-task-10303".into()),
                    privacy_tier: Some(PrivacyTier::Internal),
                }),
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x31; 32]),
            result_hash: Some([0x41; 32]),
            reveal_salt: Some([0x51; 32]),
            committed_at_height: Some(20),
            reveal_deadline_height: Some(30),
            challenge_deadline_height: Some(40),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(28),
            resolve_deadline_height: Some(52),
            challenge_bond: Some(17),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 0,
        }),
    );

    assert!(
        state.get_task(10_303).is_none(),
        "zero-version restore snapshots must fail closed instead of materializing a task object"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-version restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-version restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_zero_version_gov_param_snapshot_fails_closed_without_perturbing_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_gov_param(
        7_001,
        Some(GovParamObject {
            key_id: 7_001,
            key: "max_block_ms".into(),
            value: "1000".into(),
            version: 0,
        }),
    );

    assert!(
        state.get_param(7_001).is_none(),
        "zero-version governance restore snapshots must fail closed instead of materializing a gov param object"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-version governance restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-version governance restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_zero_id_gov_param_snapshot_fails_closed_without_perturbing_empty_root() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state.restore_gov_param(
        0,
        Some(GovParamObject {
            key_id: 0,
            key: "max_block_ms".into(),
            value: "1000".into(),
            version: 1,
        }),
    );

    assert!(
        state.get_param(0).is_none(),
        "zero-id governance restore snapshots must fail closed instead of materializing a gov param object"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "rejecting a zero-id governance restore snapshot must preserve the canonical empty-state root"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after rejecting a zero-id governance restore snapshot should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn restore_mismatched_task_id_snapshot_rewinds_live_task_and_pending_root() {
    let mut state = StateStore::new();
    state.restore_gov_param(
        1,
        Some(GovParamObject {
            key_id: 1,
            key: "resolve_authority".into(),
            value: "resolver-a,resolver-b".into(),
            version: 1,
        }),
    );

    let live_task = TaskObject {
        task_id: 10_305,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Challenged,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("live canonical task".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model-a".into()),
                model_digest: Some("cd".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test:alice".into()),
                produced_at: Some("2026-03-12T10:40:00Z".into()),
                provenance_index: Some("prov-task-live-mismatch".into()),
                privacy_tier: Some(PrivacyTier::Internal),
            }),
            metering: None,
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x31; 32]),
        result_hash: Some([0x41; 32]),
        reveal_salt: Some([0x51; 32]),
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(28),
        resolve_deadline_height: Some(52),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 3,
    };
    state.restore_task(10_305, Some(live_task));
    state
        .stage_or_confirm_resolve_approval(10_305, 3, true, "resolver-a", "resolver-a,resolver-b")
        .expect("canonical staged resolve approval should succeed");
    let staged_root = state.state_root();

    state.restore_task(
        10_305,
        Some(TaskObject {
            task_id: 10_306,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("mismatched restore snapshot".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: Some(TaskModelMetadata {
                    model_id: Some("trnm-model-a".into()),
                    model_digest: Some("cd".repeat(32)),
                    version: Some("v1".into()),
                }),
                provenance: Some(TaskProvenanceMetadata {
                    producer_did: Some("did:trnm:test:alice".into()),
                    produced_at: Some("2026-03-12T10:45:00Z".into()),
                    provenance_index: Some("prov-task-mismatch".into()),
                    privacy_tier: Some(PrivacyTier::Internal),
                }),
                metering: None,
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x31; 32]),
            result_hash: Some([0x41; 32]),
            reveal_salt: Some([0x51; 32]),
            committed_at_height: Some(20),
            reveal_deadline_height: Some(30),
            challenge_deadline_height: Some(40),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(28),
            resolve_deadline_height: Some(52),
            challenge_bond: Some(17),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 3,
        }),
    );

    let mut expected = StateStore::new();
    expected.restore_gov_param(
        1,
        Some(GovParamObject {
            key_id: 1,
            key: "resolve_authority".into(),
            value: "resolver-a,resolver-b".into(),
            version: 1,
        }),
    );

    assert!(
        state.get_task(10_305).is_none(),
        "mismatched restore target must fail closed by dropping the targeted live task slot"
    );
    assert!(
        state.pending_resolve_approval(10_305).is_none(),
        "mismatched restore target must also scrub staged pending resolve metadata"
    );
    assert_ne!(
        state.state_root(),
        staged_root,
        "dropping the targeted task slot on mismatched restore input must rewind the staged challenged-task root"
    );
    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "mismatched task-id restore input must rewind to the canonical governance-only baseline"
    );
}

#[test]
fn restore_zero_version_gov_param_snapshot_preserves_live_canonical_param_and_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_220, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let live_snapshot = state
        .get_param(7_999)
        .expect("live canonical emergency_pause object must exist");
    let root_before = state.state_root();

    state.restore_gov_param(
        7_999,
        Some(GovParamObject {
            key_id: 7_999,
            key: "emergency_pause".to_string(),
            value: "false".to_string(),
            version: 0,
        }),
    );

    let after = state
        .get_param(7_999)
        .expect("zero-version restore must not delete the live canonical governance object");
    assert_eq!(after, live_snapshot);
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "zero-version restore must preserve the canonical governance registry binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "rejecting a zero-version governance restore snapshot must preserve the prior deterministic root instead of disturbing the live canonical slot"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after rejecting a zero-version governance restore snapshot should deterministically reuse the preserved cached root"
    );
}
