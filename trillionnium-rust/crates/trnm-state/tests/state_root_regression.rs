use trnm_state::*;
use trnm_types::*;

fn install_pending_resolve_root_task(state: &mut StateStore, task_id: u64, version: u64) {
    state.restore_task(
        task_id,
        Some(TaskObject {
            task_id,
            creator: "state-root-regression".into(),
            bounty: 1,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("worker-root".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(9),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(40),
            challenge_bond: Some(5),
            challenger: Some("challenger-root".into()),
            challenge_bond_forfeited: Some(false),
            version,
        }),
    );
}

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
fn governance_proposal_status_transition_should_affect_state_root_and_match_equivalent_update_path()
{
    let proposal = GovProposalObject {
        proposal_id: 9_002,
        title: "Raise challenge success bounty".into(),
        proposer: "governance.alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    let mut transitioned = StateStore::new();
    let mut updated = StateStore::new();

    let transitioned_ref = transitioned.put_proposal_new(proposal.clone()).unwrap();
    let updated_ref = updated.put_proposal_new(proposal).unwrap();
    let baseline_root = transitioned.state_root();
    assert_eq!(
        baseline_root,
        updated.state_root(),
        "sanity: identical baseline proposal states should hash identically"
    );

    transitioned
        .transition_proposal_status(transitioned_ref, GovProposalStatus::Voting)
        .expect("proposal status transition should succeed");

    let mut manually_updated = updated
        .get_proposal(9_002)
        .expect("baseline proposal snapshot should exist");
    manually_updated.status = GovProposalStatus::Voting;
    updated
        .update_proposal(updated_ref, manually_updated)
        .expect("equivalent manual proposal status update should succeed");

    let transitioned_root = transitioned.state_root();
    assert_ne!(
        transitioned_root, baseline_root,
        "state_root should incorporate governance proposal status so draft and voting states cannot hash identically"
    );
    assert_eq!(
        transitioned_root,
        updated.state_root(),
        "equivalent proposal status transitions should produce the same deterministic root regardless of whether they use the transition helper or direct update path"
    );
}

#[test]
fn governance_proposal_title_and_proposer_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_003,
            title: "ab".into(),
            proposer: "c".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .unwrap();
    state_b
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_003,
            title: "a".into(),
            proposer: "bc".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .unwrap();

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame governance proposal title and proposer so field-boundary collisions cannot hash identically"
    );
}

#[test]
fn governance_proposal_version_must_affect_state_root_even_for_noop_payload_update() {
    let proposal = GovProposalObject {
        proposal_id: 9_004,
        title: "Raise challenge timeout".into(),
        proposer: "governance.alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    let mut baseline = StateStore::new();
    let mut updated = StateStore::new();

    baseline.put_proposal_new(proposal.clone()).unwrap();
    let updated_ref = updated.put_proposal_new(proposal).unwrap();
    let root_before = updated.state_root();

    let unchanged_payload = updated
        .get_proposal(9_004)
        .expect("proposal snapshot should exist before noop update");
    updated
        .update_proposal(updated_ref, unchanged_payload)
        .expect("noop payload update should still advance the stored proposal version");

    let root_after = updated.state_root();
    assert_ne!(
        root_after, root_before,
        "state_root must include governance proposal version so a no-op payload rewrite cannot hash identically to the original stored object"
    );
    assert_ne!(
        root_after,
        baseline.state_root(),
        "equivalent proposal payloads with different canonical stored versions must not share a state root"
    );
}

#[test]
fn governance_proposal_id_must_affect_state_root_even_when_other_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_005,
            title: "Raise fraud bond".into(),
            proposer: "governance.alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .expect("first governance proposal insertion should succeed");
    state_b
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_006,
            title: "Raise fraud bond".into(),
            proposer: "governance.alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .expect("second governance proposal insertion should succeed");

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include governance proposal_id so otherwise identical proposal payloads in distinct canonical slots cannot hash identically"
    );
}

#[test]
fn restore_applied_gov_param_rewinds_state_root_after_value_mutation() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 111, "max_block_ms".into(), "500".into())
        .expect("initial governance param insertion should succeed");
    let baseline_snapshot = state
        .get_param(111)
        .expect("baseline governance param snapshot should exist");
    let root_before = state.state_root();

    state
        .set_gov_param(0, 111, "max_block_ms".into(), "650".into())
        .expect("governance param update should succeed");
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate applied governance param values so distinct active config cannot hash identically"
    );

    state.restore_gov_param(111, Some(baseline_snapshot));
    assert_eq!(
        state.state_root(),
        root_before,
        "restore_gov_param must rewind state_root exactly after an applied governance value mutation"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after restore_gov_param should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_gov_param_none_rewinds_state_root_after_removing_applied_param_and_index() {
    let mut state = StateStore::new();

    let empty_root = state.state_root();
    state
        .set_gov_param(0, 112, "max_parallel_workers".into(), "8".into())
        .expect("governance param insertion should succeed");
    let applied_root = state.state_root();

    assert_ne!(
        applied_root, empty_root,
        "state_root should incorporate both the applied governance param object and its key index mapping"
    );

    state.restore_gov_param(112, None);

    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_gov_param(None) must rewind state_root exactly after deleting an applied governance param and its key index entry"
    );
    assert!(
        state.get_param(112).is_none(),
        "restore_gov_param(None) should remove the applied governance param object"
    );
    assert!(
        state.gov_param_string("max_parallel_workers").is_none(),
        "restore_gov_param(None) should also clear the gov_param_key_index mapping so readers cannot resolve a deleted key"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after restore_gov_param(None) should deterministically reuse the rewound cached root"
    );
}

#[test]
fn applied_gov_param_string_field_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_gov_param(
        113,
        Some(GovParamObject {
            key_id: 113,
            key: "ab".into(),
            value: "c".into(),
            version: 1,
        }),
    );
    state_b.restore_gov_param(
        113,
        Some(GovParamObject {
            key_id: 113,
            key: "a".into(),
            value: "bc".into(),
            version: 1,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame applied governance param key and value so field-boundary collisions cannot hash identically"
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
fn applied_gov_param_version_must_affect_state_root_even_when_key_and_value_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 1,
        }),
    );
    state_b.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 2,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "applied governance param version must contribute to state_root so identical key/value payloads at different canonical object versions cannot hash identically"
    );

    state_b.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 1,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original applied governance param version should rewind the deterministic root exactly"
    );
}

#[test]
fn restore_pending_gov_update_rewinds_state_root_after_value_mutation() {
    let mut state = StateStore::new();

    let baseline_snapshot = PendingGovParamUpdate {
        key_id: 114,
        key: "challenge_min_bond".into(),
        value: "120".into(),
        activate_at_height: 250,
    };
    state.restore_pending_gov_update("challenge_min_bond", Some(baseline_snapshot.clone()));
    let root_before = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 114,
            key: "challenge_min_bond".into(),
            value: "150".into(),
            activate_at_height: 275,
        }),
    );
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate pending governance queue payloads so changed staged values/timelocks cannot hash identically"
    );

    state.restore_pending_gov_update("challenge_min_bond", Some(baseline_snapshot));
    assert_eq!(
        state.state_root(),
        root_before,
        "restore_pending_gov_update must rewind state_root exactly after a pending governance payload mutation"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "repeated reads after restore_pending_gov_update should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_gov_update_none_rewinds_state_root_after_removal() {
    let mut state = StateStore::new();

    let empty_root = state.state_root();
    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 115,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 300,
        }),
    );
    let queued_root = state.state_root();

    assert_ne!(
        queued_root, empty_root,
        "state_root should incorporate pending governance queue entries so staged updates cannot be omitted from root accounting"
    );

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_pending_gov_update(None) must rewind state_root exactly after deleting a pending governance queue entry"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "restore_pending_gov_update(None) should remove the staged governance queue entry"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "repeated reads after restore_pending_gov_update(None) should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_gov_update_mismatched_snapshot_key_rewinds_state_root_by_removing_target_entry()
{
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 116,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 320,
        }),
    );
    let queued_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 116,
            key: "max_block_ms".into(),
            value: "450".into(),
            activate_at_height: 321,
        }),
    );

    let empty_root = StateStore::new().state_root();
    assert_eq!(
        state.state_root(),
        empty_root,
        "restore_pending_gov_update should fail closed by removing the requested queue entry when the supplied snapshot key mismatches the restore target"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "mismatched restore snapshot should clear the requested pending governance entry"
    );
    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched restore snapshot must not insert a different pending governance key"
    );
    assert_ne!(
        queued_root,
        state.state_root(),
        "state_root should account for fail-closed removal when a pending governance restore snapshot does not match the requested key"
    );
}

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
            metering: None,
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
        metering: None,
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
fn task_metadata_presence_bit_should_affect_state_root_even_when_nested_fields_are_empty() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_501,
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

    let mut with_empty_metadata = base_task.clone();
    with_empty_metadata.metadata = Some(TaskMetadata::default());

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(with_empty_metadata).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should distinguish absent task metadata from an explicitly present empty metadata container"
    );
}

#[test]
fn task_model_metadata_string_field_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_502,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: None,
            input_hash: None,
            model: Some(TaskModelMetadata {
                model_id: Some("ab".into()),
                model_digest: Some("c".into()),
                version: None,
            }),
            provenance: None,
            metering: None,
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
    changed_task.metadata = Some(TaskMetadata {
        note: None,
        task_type: None,
        input_hash: None,
        model: Some(TaskModelMetadata {
            model_id: Some("a".into()),
            model_digest: Some("bc".into()),
            version: None,
        }),
        provenance: None,
        metering: None,
    });

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should length-frame nested task model metadata strings so field-boundary collisions cannot hash identically"
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
        metering: None,
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
fn challenge_bond_forfeited_flag_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_002,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Challenged,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([0x22; 32]),
        result_hash: Some([0x33; 32]),
        reveal_salt: Some([0x44; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(42),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 2,
    };

    let mut changed_task = base_task.clone();
    changed_task.challenge_bond_forfeited = Some(true);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate challenge_bond_forfeited so refund-vs-forfeit challenge outcomes cannot hash identically"
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
            metering: None,
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
    changed_task
        .metadata
        .as_mut()
        .unwrap()
        .provenance
        .as_mut()
        .unwrap()
        .privacy_tier = Some(PrivacyTier::Restricted);

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
fn pending_gov_update_key_id_should_affect_state_root_even_when_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );
    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7002,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "pending governance key_id must contribute to state_root so identical staged payloads under different canonical key slots cannot hash identically"
    );

    state_b.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending governance key_id should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_string_field_boundaries_should_affect_state_root() {
    let mut st_a = StateStore::new();
    let mut st_b = StateStore::new();

    st_a.stage_or_confirm_resolve_approval(9_101, 1, true, "ab", "ab,c")
        .expect("first pending resolve snapshot should be valid");
    st_b.stage_or_confirm_resolve_approval(9_101, 1, true, "a", "a,bc")
        .expect("second pending resolve snapshot should be valid");

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "state_root should length-frame pending resolve approver and authority-set strings so field-boundary collisions cannot hash identically"
    );
}

#[test]
fn pending_resolve_task_id_must_affect_state_root_even_when_snapshot_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "authority.alpha".into(),
        authority_set: "authority.alpha,authority.beta".into(),
        task_version: 3,
    };

    state_a.restore_pending_resolve_approval(4_201, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(4_202, Some(snapshot));

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "state_root must include the pending resolve task id so identical approval payloads staged for different tasks cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        4_202,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    state_b
        .restore_pending_resolve_approval(4_201, state_a.pending_resolve_approval_snapshot(4_201));
    state_b.restore_pending_resolve_approval(4_202, None);

    assert_eq!(
        state_b.state_root(),
        root_a,
        "moving an identical pending resolve snapshot onto the original task id and removing the extra entry should rewind the deterministic root exactly"
    );
}

#[test]
fn treasury_balance_address_boundaries_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    st1.set_balance("treasury.ab", 11);
    st2.set_balance("treasury.a", 11);
    st2.set_balance("b", 0);

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "state_root should length-frame treasury balance addresses so distinct address boundaries cannot hash identically"
    );
}

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
fn treasury_balances_and_monetary_counters_should_affect_state_root_even_when_net_issuance_matches()
{
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    for st in [&mut st1, &mut st2] {
        st.set_gov_param(
            0,
            1,
            "monetary_policy_tick_interval_blocks".to_string(),
            "10".to_string(),
        )
        .unwrap();
        st.set_gov_param(
            0,
            2,
            "monetary_policy_tick_cooldown_blocks".to_string(),
            "1".to_string(),
        )
        .unwrap();
    }

    st1.set_gov_param(
        0,
        3,
        "monetary_base_issuance_per_tick".to_string(),
        "7".to_string(),
    )
    .unwrap();
    st1.set_gov_param(
        0,
        4,
        "monetary_base_burn_per_tick".to_string(),
        "5".to_string(),
    )
    .unwrap();
    st2.set_gov_param(
        0,
        3,
        "monetary_base_issuance_per_tick".to_string(),
        "9".to_string(),
    )
    .unwrap();
    st2.set_gov_param(
        0,
        4,
        "monetary_base_burn_per_tick".to_string(),
        "7".to_string(),
    )
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
fn restore_task_same_snapshot_preserves_pending_resolve_when_authority_is_still_canonical() {
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

    let task_ref = state
        .put_task_new(TaskObject {
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
        })
        .expect("task insertion should succeed");

    let mut challenged = state.get_task(task_ref.id).unwrap();
    challenged.status = TaskStatus::Challenged;
    challenged.challenger = Some("bob".into());
    challenged.challenge_bond = Some(17);
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-a",
            "resolver-a,resolver-b",
        )
        .expect("staging a first resolve approval should succeed");
    let challenged_snapshot = state.get_task(10);
    let root_with_pending = state.state_root();
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));

    state.restore_task(10, challenged_snapshot);

    assert_eq!(state.get_task(10).unwrap().version, challenged_ref.version);
    assert_eq!(state.get_task(10).unwrap().status, TaskStatus::Challenged);
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));
    assert_eq!(
        state.state_root(),
        root_with_pending,
        "same-snapshot restore re-entry should noop when the staged pending resolve snapshot still matches the canonical authority boundary"
    );
}

#[test]
fn restore_task_same_snapshot_scrubs_pending_resolve_after_proof_and_metadata_drift() {
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

    let task_ref = state
        .put_task_new(TaskObject {
            task_id: 10,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("baseline".into()),
                task_type: Some("inference".into()),
                input_hash: Some("ab".repeat(32)),
                model: None,
                provenance: None,
                metering: None,
            }),
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        })
        .expect("task insertion should succeed");

    let mut challenged = state.get_task(task_ref.id).unwrap();
    challenged.status = TaskStatus::Challenged;
    challenged.challenger = Some("bob".into());
    challenged.challenge_bond = Some(17);
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-a",
            "resolver-a,resolver-b",
        )
        .expect("staging a first resolve approval should succeed");
    let challenged_snapshot = state.get_task(10);
    let root_with_pending = state.state_root();
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));

    let mut drifted_snapshot = challenged_snapshot.clone().expect("challenged snapshot should exist");
    drifted_snapshot.proof_type = ProofType::Zk;
    drifted_snapshot.metadata = Some(TaskMetadata {
        note: Some("drifted".into()),
        task_type: Some("verification".into()),
        input_hash: Some("cd".repeat(32)),
        model: None,
        provenance: None,
        metering: None,
    });
    state.restore_task(10, Some(drifted_snapshot));

    assert_eq!(state.get_task(10).unwrap().version, challenged_ref.version);
    assert_eq!(state.get_task(10).unwrap().status, TaskStatus::Challenged);
    assert_eq!(state.pending_resolve_approval(10), None);
    assert_ne!(
        state.state_root(),
        root_with_pending,
        "same-version task snapshot drift in proof/metadata must scrub pending resolve state so restore re-entry cannot reuse a stale object boundary"
    );
}

#[test]
fn restore_task_same_snapshot_scrubs_pending_resolve_after_authority_drift() {
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

    let task_ref = state
        .put_task_new(TaskObject {
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
        })
        .expect("task insertion should succeed");

    let mut challenged = state.get_task(task_ref.id).unwrap();
    challenged.status = TaskStatus::Challenged;
    challenged.challenger = Some("bob".into());
    challenged.challenge_bond = Some(17);
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-a",
            "resolver-a,resolver-b",
        )
        .expect("staging a first resolve approval should succeed");
    let challenged_snapshot = state.get_task(10);
    let root_with_pending = state.state_root();
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));

    state.restore_gov_param(
        1,
        Some(GovParamObject {
            key_id: 1,
            key: "resolve_authority".into(),
            value: "resolver-c,resolver-d".into(),
            version: 2,
        }),
    );

    state.restore_task(10, challenged_snapshot);

    assert_eq!(state.get_task(10).unwrap().version, challenged_ref.version);
    assert_eq!(state.get_task(10).unwrap().status, TaskStatus::Challenged);
    assert_eq!(state.pending_resolve_approval(10), None);
    assert_ne!(
        state.state_root(),
        root_with_pending,
        "same-snapshot restore re-entry must scrub pending resolve state once authority drift makes the staged approval non-restorable"
    );
}

#[test]
fn restore_task_same_snapshot_scrubs_pending_resolve_after_pending_authority_drift() {
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

    let task_ref = state
        .put_task_new(TaskObject {
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
        })
        .expect("task insertion should succeed");

    let mut challenged = state.get_task(task_ref.id).unwrap();
    challenged.status = TaskStatus::Challenged;
    challenged.challenger = Some("bob".into());
    challenged.challenge_bond = Some(17);
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-a",
            "resolver-a,resolver-b",
        )
        .expect("staging a first resolve approval should succeed");
    let challenged_snapshot = state.get_task(10);
    let root_with_pending = state.state_root();
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));

    state.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 1,
            key: "resolve_authority".into(),
            value: "resolver-c,resolver-d".into(),
            activate_at_height: 42,
        }),
    );

    state.restore_task(10, challenged_snapshot);

    assert_eq!(state.get_task(10).unwrap().version, challenged_ref.version);
    assert_eq!(state.get_task(10).unwrap().status, TaskStatus::Challenged);
    assert_eq!(state.pending_resolve_approval(10), None);
    assert_ne!(
        state.state_root(),
        root_with_pending,
        "same-snapshot restore re-entry must scrub pending resolve state once a pending resolve_authority update changes the effective restore boundary"
    );
}

#[test]
fn update_task_version_change_scrubs_staged_pending_resolve_and_changes_state_root() {
    let mut state = StateStore::new();
    state
        .set_gov_param(
            0,
            1,
            "resolve_authority".into(),
            "resolver-a,resolver-b".into(),
        )
        .expect("resolve authority should be configurable for staged restore-boundary checks");

    let task_ref = state
        .put_task_new(TaskObject {
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
        })
        .expect("task insertion should succeed");

    let mut challenged = state.get_task(task_ref.id).unwrap();
    challenged.status = TaskStatus::Challenged;
    challenged.challenger = Some("bob".into());
    challenged.challenge_bond = Some(17);
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-a",
            "resolver-a,resolver-b",
        )
        .expect("staging a first resolve approval should succeed");
    let root_with_pending = state.state_root();
    assert_eq!(state.pending_resolve_approval(10), Some((true, 1)));

    let mut reopened = state.get_task(10).unwrap();
    reopened.status = TaskStatus::Open;
    reopened.challenger = None;
    reopened.challenge_bond = None;
    state
        .update_task(challenged_ref, reopened)
        .expect("version-advancing task update should succeed");

    assert_eq!(state.pending_resolve_approval(10), None);
    assert_ne!(
        state.state_root(),
        root_with_pending,
        "task version/status updates must scrub stale staged resolve approvals so restore re-entry cannot inherit an orphan snapshot"
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
fn restore_task_none_on_non_task_slot_fails_closed_and_preserves_canonical_applied_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 10_303, "max_block_ms".to_string(), "500".to_string())
        .expect("canonical applied governance param should succeed");
    let canonical_snapshot = state
        .get_param(10_303)
        .expect("canonical applied governance snapshot should exist");
    let canonical_root = state.state_root();

    state.restore_task(10_303, None);

    assert_eq!(
        state.get_param(10_303),
        Some(canonical_snapshot),
        "restore_task(None) must fail closed when pointed at a non-task object slot"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "task restore must not scrub the applied governance key index when the slot is not a task"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "restore_task(None) on a non-task slot must preserve the canonical deterministic applied-param root"
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
fn pending_resolve_task_id_slot_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    install_pending_resolve_root_task(&mut state_a, 5_148, 7);
    install_pending_resolve_root_task(&mut state_a, 5_149, 7);
    install_pending_resolve_root_task(&mut state_b, 5_148, 7);
    install_pending_resolve_root_task(&mut state_b, 5_149, 7);

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };

    state_a.restore_pending_resolve_approval(5_148, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(5_149, Some(snapshot.clone()));

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_id slot must contribute to state_root so identical approval payloads on different tasks cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(5_149, None);
    state_b.restore_pending_resolve_approval(5_148, Some(snapshot));

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending resolve task_id slot should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_slash_worker_flag_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    install_pending_resolve_root_task(&mut state_a, 5_149, 7);
    install_pending_resolve_root_task(&mut state_b, 5_149, 7);

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
fn pending_resolve_zero_confirmation_restore_scrubs_and_rewinds() {
    let mut baseline = StateStore::new();
    let mut replayed = StateStore::new();

    baseline.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    replayed.restore_pending_resolve_approval(
        5_149,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 0,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let baseline_root = baseline.state_root();
    let empty_root = StateStore::new().state_root();
    assert_eq!(
        replayed.pending_resolve_approval(5_149),
        None,
        "zero-confirmation restore snapshots must scrub instead of materializing a pending resolve entry that was never staged"
    );
    assert_eq!(
        replayed.state_root(),
        empty_root,
        "zero-confirmation restore snapshots must fail closed back to the canonical empty pending-resolve root"
    );
    replayed.restore_pending_resolve_approval(
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
        replayed.state_root(),
        baseline_root,
        "restoring the canonical staged snapshot after a zero-confirmation scrub must rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_finalized_restore_without_second_approver_scrubs_and_rewinds() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    for state in [&mut state_a, &mut state_b] {
        state.restore_task(
            5_150,
            Some(TaskObject {
                task_id: 5_150,
                creator: "creator-restore".into(),
                bounty: 1,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-restore".into()),
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
                challenger: Some("challenger-restore".into()),
                challenge_bond_forfeited: None,
                version: 7,
            }),
        );
    }

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
    assert_eq!(state_b.pending_resolve_approval(5_150), None);
    assert_ne!(
        root_a, root_b,
        "finalized restore snapshots without an encoded second approver must scrub instead of materializing a fake quorum"
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
        "restoring the original staged snapshot should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_first_approver_must_affect_state_root() {
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
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-b".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve first_approver must contribute to state_root so identical quorum state with different initial approvers cannot hash identically"
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
        "restoring the original pending resolve first_approver should rewind the deterministic root exactly"
    );
}

#[test]
fn restore_pending_resolve_snapshot_with_same_counts_but_different_authority_metadata_rewinds_state_root(
) {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5150, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5150);
    assert!(
        baseline_snapshot.is_some(),
        "sanity: snapshot should capture staged approval"
    );

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
fn restore_pending_resolve_snapshot_canonicalizes_semantically_equivalent_authority_metadata() {
    let canonical_snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };

    let mut canonical_state = StateStore::new();
    let mut replayed_state = StateStore::new();
    for state in [&mut canonical_state, &mut replayed_state] {
        state.restore_task(
            5_151,
            Some(TaskObject {
                task_id: 5_151,
                creator: "creator-restore".into(),
                bounty: 1,
                status: TaskStatus::Challenged,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-restore".into()),
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
                challenger: Some("challenger-restore".into()),
                challenge_bond_forfeited: None,
                version: 7,
            }),
        );
    }

    canonical_state.restore_pending_resolve_approval(5_151, Some(canonical_snapshot.clone()));
    replayed_state.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "ReSoLvEr-A".into(),
            authority_set: "resolver-B,ReSoLvEr-A".into(),
            task_version: 7,
        }),
    );

    assert_eq!(
        replayed_state.pending_resolve_approval_snapshot(5_151),
        Some(canonical_snapshot),
        "restore should canonicalize first approver and authority set before materializing staged pending resolve state"
    );
    assert_eq!(
        replayed_state.state_root(),
        canonical_state.state_root(),
        "semantically equivalent pending resolve restore snapshots must re-enter with the same deterministic state_root"
    );
}

#[test]
fn pending_resolve_task_slot_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let snapshot = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };

    state_a.restore_pending_resolve_approval(5_300, Some(snapshot.clone()));
    state_b.restore_pending_resolve_approval(5_301, Some(snapshot.clone()));

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_id slot must contribute to state_root so identical approval snapshots staged under different task slots cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(5_301, None);
    state_b.restore_pending_resolve_approval(5_300, Some(snapshot));
    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original pending resolve snapshot under the original task slot should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_resolve_task_version_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );
    state_b.restore_pending_resolve_approval(
        5_151,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 8,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending resolve task_version must contribute to state_root so identical approval metadata against different task revisions cannot hash identically"
    );

    state_b.restore_pending_resolve_approval(
        5_151,
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
        "restoring the original pending resolve task_version should rewind the deterministic root exactly"
    );
}

#[test]
fn insertion_order_of_multiple_pending_resolve_entries_keeps_state_root_deterministic() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let first = PendingResolveApprovalSnapshot {
        slash_worker: true,
        confirmations: 1,
        first_approver: "resolver-a".into(),
        authority_set: "resolver-a,resolver-b".into(),
        task_version: 7,
    };
    let second = PendingResolveApprovalSnapshot {
        slash_worker: false,
        confirmations: 1,
        first_approver: "resolver-c".into(),
        authority_set: "resolver-c,resolver-d".into(),
        task_version: 11,
    };

    state_a.restore_pending_resolve_approval(5_160, Some(first.clone()));
    state_a.restore_pending_resolve_approval(5_161, Some(second.clone()));

    state_b.restore_pending_resolve_approval(5_161, Some(second));
    state_b.restore_pending_resolve_approval(5_160, Some(first));

    assert_eq!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should be deterministic for equivalent pending resolve snapshots regardless of insertion order"
    );
}

#[test]
fn restore_pending_resolve_snapshot_with_same_authority_metadata_but_different_task_version_rewinds_state_root(
) {
    let mut state = StateStore::new();
    state
        .stage_or_confirm_resolve_approval(5_151, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");

    let baseline_root = state.state_root();
    let baseline_snapshot = state.pending_resolve_approval_snapshot(5_151);
    assert!(
        baseline_snapshot.is_some(),
        "sanity: snapshot should capture staged approval"
    );

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
        state.pending_resolve_approval_snapshot(5_201).is_none(),
        "restoring a pending resolve snapshot through another task slot without a matching challenged task must fail closed"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_200).is_some(),
        "mismatched-slot restore must preserve the canonical pending task slot"
    );
    assert_eq!(
        state.state_root(),
        canonical_pending_root,
        "rejecting an orphaned mismatched-slot restore must preserve the canonical pending root"
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

    let mut expected = StateStore::new();
    expected.restore_pending_resolve_approval(
        5_211,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: false,
            confirmations: 1,
            first_approver: "resolver-c".into(),
            authority_set: "resolver-c,resolver-d".into(),
            task_version: 9,
        }),
    );

    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "restore_pending_resolve_approval(None) should produce the same deterministic root as a canonical state containing only the preserved pending resolve entry"
    );

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
    assert_eq!(
        state.state_root(),
        root_with_both,
        "restoring the removed pending resolve snapshot must rewind state_root exactly to the prior two-entry root"
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
fn restore_gov_param_none_is_slot_scoped_even_with_multiple_applied_entries() {
    let mut state = StateStore::new();
    let empty_root = state.state_root();

    state
        .set_gov_param(0, 7_101, "max_block_ms".to_string(), "500".to_string())
        .expect("first applied governance param should succeed");
    let only_max_block_ms_root = state.state_root();

    state
        .set_gov_param(
            0,
            7_102,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("second applied governance param should succeed");
    let root_with_both = state.state_root();

    assert_ne!(
        root_with_both, only_max_block_ms_root,
        "sanity: adding a second applied governance param must perturb state_root"
    );

    state.restore_gov_param(7_101, None);

    assert!(
        state.get_param(7_101).is_none(),
        "slot-scoped restore should remove the targeted applied governance param object"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms"),
        None,
        "slot-scoped restore should clear the targeted key-index mapping"
    );
    assert_eq!(
        state.gov_param_string("max_parallel_workers").as_deref(),
        Some("8"),
        "slot-scoped restore must preserve unrelated applied governance params"
    );
    assert_ne!(
        state.state_root(),
        empty_root,
        "removing one applied governance param must not collapse to the empty baseline while another applied entry still exists"
    );

    let mut expected = StateStore::new();
    expected
        .set_gov_param(
            0,
            7_102,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("canonical preserved applied governance param should succeed");
    let only_max_parallel_workers_root = expected.state_root();

    assert_eq!(
        state.state_root(),
        only_max_parallel_workers_root,
        "restore_gov_param(None) should produce the same deterministic root as a canonical state containing only the preserved applied governance param"
    );

    state.restore_gov_param(
        7_101,
        Some(GovParamObject {
            key_id: 7_101,
            key: "max_block_ms".to_string(),
            value: "500".to_string(),
            version: 1,
        }),
    );
    assert_eq!(
        state.state_root(),
        root_with_both,
        "restoring the removed applied governance snapshot must rewind state_root exactly to the prior two-entry root"
    );
}

#[test]
fn restore_gov_param_mismatched_slot_preserves_canonical_applied_root() {
    let mut state = StateStore::new();

    state
        .set_gov_param(0, 7_201, "max_block_ms".to_string(), "500".to_string())
        .expect("canonical applied governance param should succeed");
    let canonical_snapshot = state
        .get_param(7_201)
        .expect("canonical applied governance param snapshot should exist");
    let canonical_root = state.state_root();

    state
        .set_gov_param(
            0,
            7_202,
            "max_parallel_workers".to_string(),
            "8".to_string(),
        )
        .expect("stale foreign applied governance param should succeed");
    let root_with_stale_foreign_slot = state.state_root();
    assert_ne!(
        root_with_stale_foreign_slot, canonical_root,
        "sanity: adding a foreign applied governance param slot must perturb state_root"
    );

    state.restore_gov_param(7_202, Some(canonical_snapshot.clone()));

    assert!(
        state.get_param(7_202).is_none(),
        "mismatched-slot restore should clear the targeted foreign applied governance slot"
    );
    assert_eq!(
        state.get_param(7_201),
        Some(canonical_snapshot.clone()),
        "mismatched-slot restore must preserve the canonical applied governance object"
    );
    assert_eq!(
        state.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "mismatched-slot restore must preserve the canonical key-index mapping"
    );
    assert_eq!(
        state.gov_param_string("max_parallel_workers"),
        None,
        "mismatched-slot restore must not alias the foreign slot into the canonical key index"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "mismatched-slot restore should fail closed back to the canonical deterministic applied-param root"
    );
    assert_eq!(
        state.state_root(),
        canonical_root,
        "repeated reads after mismatched-slot restore should deterministically reuse the canonical cached root"
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
fn monetary_gross_totals_should_affect_state_root_even_when_tick_metadata_and_net_issuance_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 9,
        net_issuance: 0,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 10,
        total_burned: 10,
        net_issuance: 0,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include gross total_minted and total_burned, not only tick metadata or net_issuance"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 9,
        net_issuance: 0,
    });

    assert_eq!(
        state_b.state_root(),
        state_a.state_root(),
        "restoring the original gross monetary totals should rewind the deterministic root exactly"
    );
}

#[test]
fn monetary_last_tick_height_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 11,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include last_tick_height so same gross/net issuance with different tick anchors cannot hash identically"
    );
}

#[test]
fn monetary_tick_count_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 4,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "state_root must include tick_count so same tick anchor and issuance totals at different monetary progression stages cannot hash identically"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original tick_count should rewind the deterministic root exactly"
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

#[test]
fn monetary_net_issuance_should_affect_state_root_even_when_other_counters_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: -5,
    });

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "state_root must include signed net_issuance so opposite monetary deltas cannot hash identically"
    );

    state_b.restore_monetary_state(MonetaryState {
        last_tick_height: 10,
        tick_count: 3,
        total_minted: 9,
        total_burned: 4,
        net_issuance: 5,
    });
    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original signed net_issuance snapshot must rewind the deterministic root exactly"
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
    assert!(state
        .pending_gov_update("challenge_success_bounty")
        .is_some());

    state.restore_pending_gov_update("challenge_min_bond", None);

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "slot-scoped restore should remove the targeted pending key"
    );
    assert!(
        state
            .pending_gov_update("challenge_success_bounty")
            .is_some(),
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
    assert!(matches!(
        challenge_outcome,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

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
fn restore_pending_gov_update_key_mismatch_fails_closed_without_aliasing_foreign_slot() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_success_bounty".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "mismatched restore snapshots must clear the requested slot instead of staging a corrupt alias"
    );
    assert!(
        state.pending_gov_update("challenge_success_bounty").is_none(),
        "mismatched restore snapshots must not materialize a foreign pending governance entry under snapshot.key"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "mismatched restore snapshots must fail closed without perturbing the deterministic root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after a mismatched restore must deterministically reuse the unchanged cached root"
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
fn pending_gov_restore_key_mismatch_clears_only_targeted_stale_slot_and_preserves_other_entries() {
    let mut state = StateStore::new();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_301,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: 7_302,
            key: "max_block_ms".to_string(),
            value: "500".to_string(),
            activate_at_height: 33,
        }),
    );

    let canonical_other_snapshot = state
        .pending_gov_update("challenge_min_bond")
        .expect("canonical pending governance entry should exist before mismatched restore");
    let root_with_both = state.state_root();

    state.restore_pending_gov_update(
        "max_block_ms",
        Some(PendingGovParamUpdate {
            key_id: 7_302,
            key: "challenge_success_bounty".to_string(),
            value: "12".to_string(),
            activate_at_height: 44,
        }),
    );

    assert!(
        state.pending_gov_update("max_block_ms").is_none(),
        "mismatched restore should fail closed by clearing only the targeted stale caller slot"
    );
    assert!(
        state.pending_gov_update("challenge_success_bounty").is_none(),
        "mismatched restore must not materialize a foreign pending governance key from snapshot.key"
    );
    assert_eq!(
        state.pending_gov_update("challenge_min_bond"),
        Some(canonical_other_snapshot.clone()),
        "mismatched restore must preserve unrelated canonical pending governance entries"
    );

    let mut expected = StateStore::new();
    expected.restore_pending_gov_update("challenge_min_bond", Some(canonical_other_snapshot));

    assert_ne!(
        state.state_root(),
        root_with_both,
        "clearing only the targeted stale caller slot must perturb the prior two-entry root"
    );
    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "after a mismatched restore, the deterministic root should match the canonical state containing only the preserved unrelated pending entry"
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

#[test]
fn pending_gov_update_key_string_boundaries_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "ab",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "ab".to_string(),
            value: "c".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "a",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "a".to_string(),
            value: "bc".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "pending governance key/value strings must be length-framed in state_root so field-boundary collisions cannot hash identically"
    );
}

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

#[test]
fn cloned_cached_state_restore_roundtrip_rewinds_applied_gov_param_root_without_aliasing_original_index(
) {
    let mut original = StateStore::new();
    original
        .set_gov_param(0, 7_901, "max_block_ms".into(), "500".into())
        .expect("baseline applied governance param should succeed");

    let baseline_root = original.state_root();
    let baseline_snapshot = original
        .get_param(7_901)
        .expect("baseline applied governance snapshot should exist");
    let mut cloned = original.clone();

    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "cloned state should preserve the canonical cached applied-governance root before mutation"
    );
    assert_eq!(
        cloned.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "cloned state should preserve the canonical key-index mapping before mutation"
    );

    cloned.restore_gov_param(
        7_901,
        Some(GovParamObject {
            key_id: 7_901,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: baseline_snapshot.version,
        }),
    );

    let mutated_clone_root = cloned.state_root();
    assert_ne!(
        mutated_clone_root, baseline_root,
        "changing an applied governance key through restore_gov_param must perturb the cloned root because both object payload and key index are state-root inputs"
    );
    assert_eq!(
        cloned.gov_param_string("max_block_ms"),
        None,
        "clone-local restore mutation should rewrite the clone key index away from the original key"
    );
    assert_eq!(
        cloned.gov_param_string("max_parallel_workers").as_deref(),
        Some("8"),
        "clone-local restore mutation should expose the replacement applied governance key only inside the clone"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "clone-local applied governance mutation must not alias back into the original cached root"
    );
    assert_eq!(
        original.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "clone-local applied governance mutation must not rewrite the original key-index mapping"
    );

    cloned.restore_gov_param(7_901, Some(baseline_snapshot.clone()));

    assert_eq!(
        cloned.gov_param_string("max_block_ms").as_deref(),
        Some("500"),
        "restoring the original applied governance snapshot should restore the canonical key-index mapping in the clone"
    );
    assert_eq!(
        cloned.gov_param_string("max_parallel_workers"),
        None,
        "restoring the original applied governance snapshot should remove the clone-only replacement key"
    );
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "restoring the cloned applied governance snapshot must rewind state_root exactly to the original canonical baseline"
    );
    assert_eq!(
        cloned.state_root(),
        baseline_root,
        "repeated reads after clone-local applied governance restore should deterministically reuse the rewound cached root"
    );
    assert_eq!(
        original.state_root(),
        baseline_root,
        "the original state's cached root must remain canonical after the clone restores its applied governance snapshot"
    );
}
