use trnm_state::*;
use trnm_types::*;

fn pending_gov_base_value(key: &str) -> &'static str {
    match key {
        "max_block_ms" => "500",
        "max_parallel_workers" => "32",
        "min_worker_stake" => "1000",
        "challenge_min_bond" => "100",
        "challenge_success_bounty" => "10",
        _ => panic!("missing pending gov base fixture for {key}"),
    }
}

fn install_pending_gov_base(state: &mut StateStore, key_id: u64, key: &str) {
    if state.get_param(key_id).is_none() {
        state.restore_gov_param(
            key_id,
            Some(GovParamObject {
                key_id,
                key: key.to_string(),
                value: pending_gov_base_value(key).to_string(),
                version: 1,
            }),
        );
    }
}

fn restore_pending_gov_update_with_base(
    state: &mut StateStore,
    key: &str,
    snapshot: PendingGovParamUpdate,
) {
    if snapshot.key == key {
        install_pending_gov_base(state, snapshot.key_id, key);
    }
    state.restore_pending_gov_update(key, Some(snapshot));
}

#[test]
fn node_recovery_checkpoint_rejects_wal_entry_hash_with_edge_whitespace() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.wal_entry_hash_hex = format!(" {} ", checkpoint.wal_entry_hash_hex);

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint wal_entry_hash_hex with edge whitespace so restart-time checkpoint proofs preserve canonical digest surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_wal_entry_hash_with_zero_width_layout_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.wal_entry_hash_hex.push('\u{200B}');

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint wal_entry_hash_hex with zero-width layout drift so restart-time checkpoint proofs preserve byte-canonical WAL digest surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_blank_wal_entry_hash() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: String::new(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject blank checkpoint wal_entry_hash_hex so restart-time checkpoint proofs cannot bind to a missing WAL digest surface"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_wal_entry_hash_with_non_hex_ascii_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: "zz".repeat(32),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint wal_entry_hash_hex with non-hex ascii drift so restart-time checkpoint proofs preserve canonical digest encoding"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_wal_entry_hash_with_newline_control_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.wal_entry_hash_hex.push('\n');

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint wal_entry_hash_hex with control-character drift so restart-time checkpoint proofs preserve byte-canonical WAL digest surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_state_root_with_zero_width_layout_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "state-root-1".into(),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.state_root_hex.push('\u{200B}');

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint state_root_hex with zero-width layout drift so restart-time checkpoint proofs cannot depend on locale-sensitive legacy state-root surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_state_root_with_newline_control_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "state-root-1".into(),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.state_root_hex.push('\n');

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint state_root_hex with control-character drift so restart-time checkpoint proofs cannot bind to newline-variant state-root surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_wal_entry_hash_with_uppercase_hex_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.wal_entry_hash_hex = checkpoint.wal_entry_hash_hex.to_uppercase();

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint wal_entry_hash_hex with uppercase digest drift so restart-time checkpoint proofs preserve canonical lower-hex WAL bindings"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_state_root_with_uppercase_hex_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let mut checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    checkpoint.state_root_hex = checkpoint.state_root_hex.to_uppercase();

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint state_root_hex with uppercase digest drift so restart-time checkpoint proofs preserve canonical lower-hex state-root surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_proposal_hash_with_edge_whitespace() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: " proposal-1 ".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject WAL proposal identities with edge whitespace so restart-time checkpoint proofs cannot accept non-canonical proposal surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_proposal_hash_with_zero_width_layout_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: format!("proposal-1{}", '\u{200B}'),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject WAL proposal identities with zero-width layout drift so restart-time checkpoint proofs cannot accept visually identical but non-canonical proposal surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_proposal_hash_with_newline_control_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1\n".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject WAL proposal identities with newline control drift so restart-time checkpoint proofs cannot accept non-canonical control-character proposal surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_edge_whitespace() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some(format!(" {} ", "01".repeat(32))),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex with edge whitespace so restart-time checkpoint linkage remains byte-canonical"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_missing_non_genesis_prev_hash() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL metadata without prev_hash_hex so restart-time checkpoint linkage cannot lose its predecessor proof"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_zero_width_layout_drift() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some(format!("{}{}", "01".repeat(32), '\u{200B}')),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex with zero-width layout drift so restart-time checkpoint linkage preserves byte-canonical predecessor bindings"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_newline_control_drift() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some(format!("{}\n", "01".repeat(32))),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex with control-character drift so restart-time checkpoint linkage preserves canonical predecessor bindings"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_carriage_return_control_drift() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some(format!("{}\r", "01".repeat(32))),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex with carriage-return drift so checkpoint sidecars cannot revive CRLF-tainted predecessor bindings during restart-time recovery"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_uppercase_hex_drift() {
    let wal_entry = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("01".repeat(32).to_uppercase()),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex with uppercase digest drift so restart-time checkpoint linkage preserves canonical lower-hex predecessor bindings"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_blank_state_root() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "state-root-1".into(),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: String::new(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject blank checkpoint state_root_hex so restart-time checkpoint proofs cannot bind to a missing state-root surface"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_state_root_with_non_hex_ascii_drift() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: "zz".repeat(32),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint state_root_hex with non-hex ascii drift so restart-time checkpoint proofs preserve canonical lower-hex state-root surfaces"
    );
}

#[test]
fn node_recovery_checkpoint_rejects_state_root_with_edge_whitespace() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "state-root-1".into(),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: format!(" {} ", wal_entry.state_root_hex),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };

    let got = verify_wal_and_find_checkpoint_node_recovery(&[checkpoint], &[wal_entry]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject checkpoint state_root_hex with edge whitespace so restart-time checkpoint proofs preserve canonical digest surfaces"
    );
}

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

fn task_with_boundary_metering(workload_class: &str, metering_schema: &str) -> TaskObject {
    TaskObject {
        task_id: 8_901,
        creator: "alice".into(),
        bounty: 99,
        status: TaskStatus::Assigned,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("boundary metering".into()),
            task_type: Some("inference".into()),
            input_hash: Some("aa".repeat(32)),
            model: Some(TaskModelMetadata {
                model_id: Some("trnm-model-b".into()),
                model_digest: Some("bb".repeat(32)),
                version: Some("v1".into()),
            }),
            provenance: Some(TaskProvenanceMetadata {
                producer_did: Some("did:trnm:test:alice".into()),
                produced_at: Some("2026-03-12T08:00:00Z".into()),
                provenance_index: Some("prov-task-boundary".into()),
                privacy_tier: Some(PrivacyTier::Public),
            }),
            metering: Some(TaskMeteringSnapshot {
                workload_class: workload_class.into(),
                metering_schema: metering_schema.into(),
                policy_snapshot_version: 1,
                receipt_hash: "cc".repeat(32),
                prompt_tokens: 16,
                generated_tokens: 8,
                decode_steps: 6,
                kv_bytes_moved: 1024,
                normalized_work_units: 99,
                prompt_token_weight: 1,
                generated_token_weight: 2,
                decode_step_weight: 3,
                kv_byte_weight: 4,
                min_accept_work_units: 10,
                challenge_success_bounty_base: 11,
                challenge_success_bounty_per_work_unit_num: 13,
                challenge_success_bounty_per_work_unit_den: 17,
                worker_completion_bonus_per_work_unit_num: 19,
                worker_completion_bonus_per_work_unit_den: 23,
                worker_slash_rebate_per_work_unit_num: 29,
                worker_slash_rebate_per_work_unit_den: 31,
            }),
        }),
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(52),
        challenge_bond: Some(7),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    }
}

#[test]
fn task_creator_and_worker_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .put_task_new(TaskObject {
            task_id: 8_005,
            creator: "ab".into(),
            bounty: 99,
            status: TaskStatus::Assigned,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("c".into()),
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
        .unwrap();
    state_b
        .put_task_new(TaskObject {
            task_id: 8_005,
            creator: "a".into(),
            bounty: 99,
            status: TaskStatus::Assigned,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("bc".into()),
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
        .unwrap();

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame task creator and worker so adjacent string boundaries cannot hash identically"
    );
}

#[test]
fn task_metering_snapshot_field_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let task_a = task_with_boundary_metering("ab", "c");
    let mut task_b = task_with_boundary_metering("a", "bc");
    task_b.task_id = task_a.task_id;

    state_a.put_task_new(task_a).unwrap();
    state_b.put_task_new(task_b).unwrap();

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame metering workload_class and metering_schema so adjacent string boundaries cannot collide"
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
fn applied_gov_param_embedded_key_id_must_affect_state_root_even_when_slot_key_and_value_match() {
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
            key_id: 115,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 1,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "applied governance embedded key_id must contribute to state_root so malformed restore snapshots cannot alias a canonical applied slot"
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
    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        baseline_snapshot.clone(),
    );
    let root_before = state.state_root();

    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 114,
            key: "challenge_min_bond".into(),
            value: "150".into(),
            activate_at_height: 275,
        },
    );
    let root_after = state.state_root();

    assert_ne!(
        root_before, root_after,
        "state_root should incorporate pending governance queue payloads so changed staged values/timelocks cannot hash identically"
    );

    restore_pending_gov_update_with_base(&mut state, "challenge_min_bond", baseline_snapshot);
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

    install_pending_gov_base(&mut state, 115, "challenge_min_bond");
    let empty_root = state.state_root();
    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 115,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 300,
        },
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

    install_pending_gov_base(&mut state, 116, "challenge_min_bond");
    let empty_root = state.state_root();
    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 116,
            key: "challenge_min_bond".into(),
            value: "120".into(),
            activate_at_height: 320,
        },
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

    let empty_root = empty_root;
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
fn restore_pending_gov_update_rejects_non_sensitive_emergency_pause_snapshot_and_rewinds_state_root(
) {
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
        "emergency_pause",
        Some(PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 321,
        }),
    );

    assert_eq!(
        state.pending_gov_update("emergency_pause"),
        None,
        "non-sensitive emergency_pause metadata must not be restorable into the pending governance queue"
    );
    assert_eq!(
        state.state_root(),
        queued_root,
        "rejecting non-sensitive pending governance metadata must leave unrelated queued proof material untouched"
    );
}

#[test]
fn restore_pending_gov_update_rejects_bare_emergency_pause_alias_in_resolve_authority_snapshot() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state
        .stage_or_confirm_resolve_approval(5_241_1, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("initial staged resolve approval should succeed");
    let pending_root = state.state_root();
    assert_ne!(
        pending_root, baseline_root,
        "sanity: staged pending resolve approval must perturb the root before bare emergency_pause alias replay"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_241_1).is_some(),
        "sanity: pending resolve approval should exist before the fail-closed bare emergency_pause alias restore"
    );

    state.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 7,
            key: "resolve_authority".into(),
            value: "resolver-a,Emergency_Pause".into(),
            activate_at_height: 320,
        }),
    );

    assert!(
        state.pending_gov_update("resolve_authority").is_none(),
        "bare emergency_pause alias resolve_authority restore snapshots must fail closed instead of materializing a queued governance update"
    );
    assert!(
        state.pending_resolve_approval_snapshot(5_241_1).is_none(),
        "rejecting a bare emergency_pause alias resolve_authority restore snapshot must scrub staged pending resolve metadata"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "rejecting a bare emergency_pause alias resolve_authority restore snapshot must rewind state_root to the pre-staged baseline"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after bare emergency_pause alias resolve_authority rejection should deterministically reuse the rewound cached root"
    );
}

#[test]
fn restore_pending_gov_update_rejects_snapshot_key_id_shadowing_live_governance_metadata() {
    let mut state = StateStore::new();

    let bootstrap = state
        .set_gov_param(150, 116, "challenge_min_bond".into(), "120".into())
        .expect("bootstrap challenge_min_bond write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = state
        .set_gov_param(170, 116, "challenge_min_bond".into(), "120".into())
        .expect("challenge_min_bond write should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 117,
            key: "challenge_min_bond".into(),
            value: "121".into(),
            activate_at_height: 320,
        }),
    );

    assert_eq!(
        state.pending_gov_update("challenge_min_bond"),
        None,
        "restore must fail closed when pending governance proof material rebinds a live key onto a shadow key id"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "rejecting shadow key-id restore metadata must preserve the live governance state root"
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
fn task_metering_snapshot_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_503,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
                workload_class: "gpu.inference".into(),
                metering_schema: "llm/v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 10,
                generated_tokens: 20,
                decode_steps: 30,
                kv_bytes_moved: 40,
                normalized_work_units: 50,
                prompt_token_weight: 1,
                generated_token_weight: 2,
                decode_step_weight: 3,
                kv_byte_weight: 4,
                min_accept_work_units: 5,
                challenge_success_bounty_base: 6,
                challenge_success_bounty_per_work_unit_num: 7,
                challenge_success_bounty_per_work_unit_den: 8,
                worker_completion_bonus_per_work_unit_num: 9,
                worker_completion_bonus_per_work_unit_den: 10,
                worker_slash_rebate_per_work_unit_num: 11,
                worker_slash_rebate_per_work_unit_den: 12,
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
    changed_task
        .metadata
        .as_mut()
        .expect("task metadata should exist")
        .metering
        .as_mut()
        .expect("task metering snapshot should exist")
        .normalized_work_units = 51;

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "state_root must include task metering snapshot evidence so checkpoint audit surfaces cannot ignore metering-only task metadata changes"
    );
}

#[test]
fn task_metering_min_accept_work_units_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_504,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint acceptance threshold snapshot".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
                workload_class: "gpu.inference".into(),
                metering_schema: "llm/v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 10,
                generated_tokens: 20,
                decode_steps: 30,
                kv_bytes_moved: 40,
                normalized_work_units: 50,
                prompt_token_weight: 1,
                generated_token_weight: 2,
                decode_step_weight: 3,
                kv_byte_weight: 4,
                min_accept_work_units: 5,
                challenge_success_bounty_base: 6,
                challenge_success_bounty_per_work_unit_num: 7,
                challenge_success_bounty_per_work_unit_den: 8,
                worker_completion_bonus_per_work_unit_num: 9,
                worker_completion_bonus_per_work_unit_den: 10,
                worker_slash_rebate_per_work_unit_num: 11,
                worker_slash_rebate_per_work_unit_den: 12,
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
    changed_task
        .metadata
        .as_mut()
        .expect("task metadata should exist")
        .metering
        .as_mut()
        .expect("task metering snapshot should exist")
        .min_accept_work_units = 6;

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "state_root must include task metering min_accept_work_units so acceptance-threshold drift cannot preserve the same canonical audit root"
    );
}

#[test]
fn task_metering_reward_terms_should_affect_state_root_even_when_usage_metrics_match() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 6_504_1,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Open,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: Some("checkpoint incentive snapshot".into()),
            task_type: Some("inference".into()),
            input_hash: Some("ab".repeat(32)),
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
                workload_class: "gpu.inference".into(),
                metering_schema: "llm/v1".into(),
                policy_snapshot_version: 3,
                receipt_hash: "ef".repeat(32),
                prompt_tokens: 10,
                generated_tokens: 20,
                decode_steps: 30,
                kv_bytes_moved: 40,
                normalized_work_units: 50,
                prompt_token_weight: 1,
                generated_token_weight: 2,
                decode_step_weight: 3,
                kv_byte_weight: 4,
                min_accept_work_units: 5,
                challenge_success_bounty_base: 6,
                challenge_success_bounty_per_work_unit_num: 7,
                challenge_success_bounty_per_work_unit_den: 8,
                worker_completion_bonus_per_work_unit_num: 9,
                worker_completion_bonus_per_work_unit_den: 10,
                worker_slash_rebate_per_work_unit_num: 11,
                worker_slash_rebate_per_work_unit_den: 12,
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
    let metering = changed_task
        .metadata
        .as_mut()
        .expect("task metadata should exist")
        .metering
        .as_mut()
        .expect("task metering snapshot should exist");
    metering.challenge_success_bounty_base = 7;
    metering.worker_completion_bonus_per_work_unit_num = 10;

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "state_root must include task metering reward terms so incentive-schedule drift cannot preserve the same canonical audit root"
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

    restore_pending_gov_update_with_base(
        &mut st1,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        },
    );
    install_pending_gov_base(&mut st2, 7001, "challenge_min_bond");
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
fn pending_gov_update_string_field_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "ab",
        Some(PendingGovParamUpdate {
            key_id: 7_000,
            key: "ab".into(),
            value: "c".into(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "a",
        Some(PendingGovParamUpdate {
            key_id: 7_000,
            key: "a".into(),
            value: "bc".into(),
            activate_at_height: 1_020,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame pending governance key/value strings so field-boundary collisions cannot hash identically"
    );
}

#[test]
fn pending_gov_update_key_id_should_affect_state_root_even_when_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    restore_pending_gov_update_with_base(
        &mut state_a,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7002,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        },
    );

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "pending governance key_id must contribute to state_root so identical staged payloads under different canonical key slots cannot hash identically"
    );

    let mut rewound = StateStore::new();
    restore_pending_gov_update_with_base(
        &mut rewound,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7001,
            key: "challenge_min_bond".into(),
            value: "5000".into(),
            activate_at_height: 1020,
        },
    );

    assert_eq!(
        rewound.state_root(),
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
fn pending_resolve_canonical_actor_forms_should_keep_state_root_stable() {
    let mut staged = StateStore::new();
    let mut restored = StateStore::new();

    staged.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 7_501,
            key: "resolve_authority".into(),
            value: "authority.alpha,authority.beta".into(),
            activate_at_height: 10,
        }),
    );
    restored.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 7_501,
            key: "resolve_authority".into(),
            value: "authority.alpha,authority.beta".into(),
            activate_at_height: 10,
        }),
    );

    staged
        .stage_or_confirm_resolve_approval(
            9_102,
            1,
            true,
            "AUTHORITY.ALPHA",
            "AUTHORITY.BETA,AUTHORITY.ALPHA",
        )
        .expect("staging should canonicalize equivalent pending resolve authority metadata");
    restored.restore_pending_resolve_approval(
        9_102,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        staged.pending_resolve_first_approver(9_102).as_deref(),
        Some("authority.alpha"),
        "staged pending resolve approvals should store canonical approver ids"
    );
    assert_eq!(
        staged
            .pending_resolve_approval_snapshot(9_102)
            .expect("staged snapshot should exist")
            .authority_set,
        "authority.alpha,authority.beta",
        "staged pending resolve approvals should store canonical authority ordering"
    );
    assert_eq!(
        restored.state_root(),
        staged.state_root(),
        "state_root should ignore case and ordering noise once pending resolve authority metadata is canonicalized"
    );
}

#[test]
fn pending_resolve_task_id_must_affect_state_root_even_when_snapshot_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    let restore_task = |task_id| TaskObject {
        task_id,
        creator: "alice".into(),
        bounty: 42,
        status: TaskStatus::Challenged,
        proof_type: ProofType::Fraud,
        metadata: None,
        worker: Some("worker-a".into()),
        committed_hash: Some([0x11; 32]),
        result_hash: Some([0x22; 32]),
        reveal_salt: Some([0x33; 32]),
        committed_at_height: Some(20),
        reveal_deadline_height: Some(30),
        challenge_deadline_height: Some(40),
        challenge_window_blocks_snapshot: Some(12),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(52),
        challenge_bond: Some(17),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 3,
    };

    for state in [&mut state_a, &mut state_b] {
        state.restore_task(4_201, Some(restore_task(4_201)));
        state.restore_task(4_202, Some(restore_task(4_202)));
    }

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
fn pending_resolve_task_version_must_affect_state_root_even_when_other_snapshot_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_resolve_approval(
        4_201,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 3,
        }),
    );
    state_b.restore_pending_resolve_approval(
        4_201,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority.alpha".into(),
            authority_set: "authority.alpha,authority.beta".into(),
            task_version: 4,
        }),
    );

    let root_a = state_a.state_root();
    assert_ne!(
        root_a,
        state_b.state_root(),
        "state_root must include the pending resolve task version so identical approval payloads for different task snapshots cannot hash identically"
    );

    state_b
        .restore_pending_resolve_approval(4_201, state_a.pending_resolve_approval_snapshot(4_201));
    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the same pending resolve task version must rewind state_root exactly"
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
fn zero_challenge_forfeits_balance_canonicalizes_to_missing_entry_even_with_other_pending_and_monetary_state(
) {
    let mut missing = StateStore::new();
    let mut explicit_zero = StateStore::new();

    for state in [&mut missing, &mut explicit_zero] {
        state.set_balance("treasury.challenge_escrow", 17);
        state.set_balance("treasury.worker_slashes", 19);
        state.restore_pending_gov_update(
            "challenge_min_bond",
            Some(PendingGovParamUpdate {
                key_id: 304,
                key: "challenge_min_bond".into(),
                value: "180".into(),
                activate_at_height: 262,
            }),
        );
        state.restore_pending_resolve_approval(
            4_202,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "authority.beta".into(),
                authority_set: "authority.alpha,authority.beta".into(),
                task_version: 6,
            }),
        );
        state.restore_monetary_state(MonetaryState {
            last_tick_height: 93,
            tick_count: 7,
            total_minted: 31,
            total_burned: 8,
            net_issuance: 23,
        });
    }

    let missing_root = missing.state_root();
    explicit_zero.set_balance("treasury.challenge_forfeits", 0);

    assert_eq!(
        explicit_zero.balance_of("treasury.challenge_forfeits"),
        0,
        "sanity: explicit zero challenge forfeits balance should still read back as zero"
    );
    assert_eq!(
        explicit_zero.state_root(),
        missing_root,
        "state_root must treat zero challenge forfeits balance the same as a missing entry even when other pending, collateral, and monetary state is present"
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

    let mut drifted_snapshot = challenged_snapshot
        .clone()
        .expect("challenged snapshot should exist");
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
fn restore_pending_gov_update_identical_resolve_authority_snapshot_is_reentry_noop() {
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

    let snapshot = PendingGovParamUpdate {
        key_id: 1,
        key: "resolve_authority".into(),
        value: "resolver-c,resolver-d".into(),
        activate_at_height: 42,
    };
    state.restore_pending_gov_update("resolve_authority", Some(snapshot.clone()));
    assert_eq!(state.pending_resolve_approval(10), None);

    state
        .stage_or_confirm_resolve_approval(
            10,
            challenged_ref.version,
            true,
            "resolver-c",
            "resolver-c,resolver-d",
        )
        .expect("staging resolve approval after boundary scrub should succeed");
    let root_with_pending = state.state_root();
    let pending_snapshot = state.pending_resolve_approval_snapshot(10);

    state.restore_pending_gov_update("resolve_authority", Some(snapshot));

    assert_eq!(
        state.pending_resolve_approval_snapshot(10),
        pending_snapshot
    );
    assert_eq!(state.state_root(), root_with_pending);
}

#[test]
fn restore_pending_resolve_identical_snapshot_revalidates_effective_authority_boundary() {
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
        .expect("staging the initial resolve approval should succeed");
    let stale_snapshot = state
        .pending_resolve_approval_snapshot(10)
        .expect("stale pending resolve snapshot should exist before authority drift");
    let root_with_stale_pending = state.state_root();

    state.restore_gov_param(
        1,
        Some(GovParamObject {
            key_id: 1,
            key: "resolve_authority".into(),
            value: "resolver-c,resolver-d".into(),
            version: 2,
        }),
    );

    state.restore_pending_resolve_approval(10, Some(stale_snapshot));

    assert_eq!(
        state.pending_resolve_approval(10),
        None,
        "restoring an identical stale pending snapshot must revalidate the effective resolve authority boundary and scrub the orphaned approval"
    );
    assert_ne!(
        state.state_root(),
        root_with_stale_pending,
        "scrubbing the stale pending resolve snapshot after authority drift must perturb the deterministic root"
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
fn restore_task_incomplete_metering_metadata_fails_closed_and_rewinds_to_baseline_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_task(
        10_303,
        Some(TaskObject {
            task_id: 10_303,
            creator: "alice".into(),
            bounty: 100,
            status: TaskStatus::Open,
            proof_type: ProofType::Fraud,
            metadata: Some(TaskMetadata {
                note: Some("audit-proof snapshot".into()),
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
                metering: Some(TaskMeteringSnapshot {
                    workload_class: "llm_inference".into(),
                    metering_schema: "llm_token_meter_v1".into(),
                    policy_snapshot_version: 1,
                    receipt_hash: "   ".into(),
                    prompt_tokens: 10,
                    generated_tokens: 20,
                    decode_steps: 30,
                    kv_bytes_moved: 40,
                    normalized_work_units: 50,
                    prompt_token_weight: 1,
                    generated_token_weight: 2,
                    decode_step_weight: 3,
                    kv_byte_weight: 4,
                    min_accept_work_units: 5,
                    challenge_success_bounty_base: 6,
                    challenge_success_bounty_per_work_unit_num: 7,
                    challenge_success_bounty_per_work_unit_den: 8,
                    worker_completion_bonus_per_work_unit_num: 9,
                    worker_completion_bonus_per_work_unit_den: 10,
                    worker_slash_rebate_per_work_unit_num: 11,
                    worker_slash_rebate_per_work_unit_den: 12,
                }),
            }),
            worker: Some("worker-a".into()),
            committed_hash: Some([0x21; 32]),
            result_hash: Some([0x34; 32]),
            reveal_salt: Some([0x55; 32]),
            committed_at_height: Some(20),
            reveal_deadline_height: Some(30),
            challenge_deadline_height: Some(40),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: None,
            resolve_deadline_height: Some(52),
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }),
    );

    assert!(
        state.get_task(10_303).is_none(),
        "restore_task should fail closed when metering proof metadata is incomplete"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "rejecting incomplete metering proof metadata must preserve the canonical baseline state root"
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
fn restore_task_zero_version_fails_closed_and_rewinds_staged_pending_root() {
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
    install_pending_resolve_root_task(&mut state, 10_304, 7);
    state
        .stage_or_confirm_resolve_approval(10_304, 7, true, "resolver-a", "resolver-a,resolver-b")
        .expect("canonical staged resolve approval should succeed");

    let staged_root = state.state_root();
    let mut zero_version_snapshot = state
        .get_task(10_304)
        .expect("canonical challenged task snapshot should exist");
    zero_version_snapshot.version = 0;

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

    state.restore_task(10_304, Some(zero_version_snapshot));

    assert!(
        state.get_task(10_304).is_none(),
        "restore_task should fail closed by dropping a zero-version task snapshot instead of materializing it"
    );
    assert!(
        state.pending_resolve_approval(10_304).is_none(),
        "restore_task should scrub staged pending resolve metadata when the replayed task snapshot carries version zero"
    );
    assert_ne!(
        state.state_root(),
        staged_root,
        "a zero-version replay must not preserve the staged challenged-task state root"
    );
    assert_eq!(
        state.state_root(),
        expected.state_root(),
        "dropping the invalid task snapshot and its staged approval should rewind state_root to the canonical governance-only baseline"
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
    assert_eq!(state_b.pending_resolve_first_approver(5_150), None);
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
fn pending_resolve_zero_confirmation_restore_scrubs_and_rewinds_followup() {
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
            confirmations: 0,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_eq!(state_b.pending_resolve_approval(5_151), None);
    assert_ne!(
        root_a, root_b,
        "zero-confirmation restore snapshots must scrub instead of materializing an incomplete pending resolve quorum"
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
        "restoring the original staged snapshot should rewind the deterministic root exactly after scrubbing an incomplete snapshot"
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
        .set_gov_param(
            98_300,
            7_310,
            "resolve_authority".into(),
            "resolver-a,resolver-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    state
        .set_gov_param(
            98_320,
            7_310,
            "resolve_authority".into(),
            "resolver-a,resolver-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    state
        .put_task_new(TaskObject {
            task_id: 5_150,
            creator: "alice".into(),
            bounty: 42,
            status: TaskStatus::Challenged,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some("worker-a".into()),
            committed_hash: Some([0x11; 32]),
            result_hash: Some([0x22; 32]),
            reveal_salt: Some([0x33; 32]),
            committed_at_height: Some(10),
            reveal_deadline_height: Some(20),
            challenge_deadline_height: Some(30),
            challenge_window_blocks_snapshot: Some(12),
            challenged_at_height: Some(25),
            resolve_deadline_height: Some(42),
            challenge_bond: Some(17),
            challenger: Some("bob".into()),
            challenge_bond_forfeited: Some(false),
            version: 7,
        })
        .expect("challenged task should exist before restore rewind");
    state
        .stage_or_confirm_resolve_approval(5150, 1, true, "resolver-a", "resolver-a,resolver-b")
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
fn restore_pending_resolve_invalid_snapshot_fails_closed_to_canonical_root() {
    let mut state = StateStore::new();

    let empty_root = state.state_root();
    state.restore_pending_resolve_approval(
        5_199,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a,resolver-b".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 7,
        }),
    );

    assert!(
        state.pending_resolve_approval_snapshot(5_199).is_none(),
        "restore_pending_resolve_approval should fail closed instead of materializing a malformed checkpoint snapshot"
    );
    assert_eq!(
        state.state_root(),
        empty_root,
        "malformed pending resolve checkpoint evidence must not perturb the canonical empty root"
    );
}

#[test]
fn restore_pending_resolve_outer_object_version_drift_is_state_root_noop() {
    let mut state = StateStore::new();
    let task_ref = state
        .put_task_new(TaskObject {
            task_id: 5_199,
            creator: "state-root-regression".into(),
            bounty: 1,
            status: TaskStatus::Open,
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
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        })
        .expect("task insertion should succeed");
    let mut challenged = state.get_task(5_199).expect("task should exist");
    challenged.status = TaskStatus::Challenged;
    challenged.challenged_at_height = Some(25);
    challenged.resolve_deadline_height = Some(40);
    challenged.challenge_bond = Some(5);
    challenged.challenger = Some("challenger-root".into());
    let challenged_ref = state
        .update_task(task_ref, challenged)
        .expect("task challenge transition should succeed");
    let drifted_root = state.state_root();

    state.restore_pending_resolve_approval(
        5_199,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "resolver-a".into(),
            authority_set: "resolver-a,resolver-b".into(),
            task_version: 1,
        }),
    );

    assert!(
        state.pending_resolve_approval_snapshot(5_199).is_none(),
        "pending resolve restore must fail closed when the outer object version has drifted away from the snapshot's task_version"
    );
    assert_eq!(
        state.get_ref(5_199).map(|reference| reference.version),
        Some(challenged_ref.version),
        "rejecting the stale pending restore must not silently rewrite the drifted outer object version"
    );
    assert_eq!(
        state.state_root(),
        drifted_root,
        "rejecting pending resolve restore across an outer object-version drift must remain a state-root no-op"
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
fn restore_gov_param_rejects_noncanonical_emergency_pause_key_id_without_aliasing_slot() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_gov_param(
        7_998,
        Some(GovParamObject {
            key_id: 7_998,
            key: "emergency_pause".to_string(),
            value: "true".to_string(),
            version: 1,
        }),
    );

    assert!(
        state.get_param(7_998).is_none(),
        "restore must fail closed when emergency_pause arrives through a non-canonical key id"
    );
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        None,
        "non-canonical emergency_pause restore must not alias into the canonical governance key registry"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "rejecting a non-canonical emergency_pause restore must preserve the baseline deterministic root"
    );
}

#[test]
fn restore_gov_param_rejects_invalid_false_emergency_pause_literal_without_deleting_live_canonical_param() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_205, 7_999, "emergency_pause".into(), "true".into())
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
            value: "False".to_string(),
            version: live_snapshot.version,
        }),
    );

    let after = state
        .get_param(7_999)
        .expect("invalid false restore must not delete the live canonical governance object");
    assert_eq!(after.key, live_snapshot.key);
    assert_eq!(after.value, live_snapshot.value);
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "invalid false restore must preserve the canonical governance registry binding"
    );
    assert!(
        state.is_emergency_paused(),
        "invalid false restore must preserve the active pause state"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "invalid false restore must preserve the prior deterministic root instead of mutating the live canonical governance slot"
    );
}

#[test]
fn restore_gov_param_rejects_noncanonical_snapshot_without_deleting_live_canonical_param() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_200, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let live_snapshot = state
        .get_param(7_999)
        .expect("live canonical emergency_pause object must exist");
    let root_before = state.state_root();

    state.restore_gov_param(
        7_999,
        Some(GovParamObject {
            key_id: 7_999,
            key: " emergency_pause".to_string(),
            value: "false".to_string(),
            version: live_snapshot.version + 1,
        }),
    );

    let after = state
        .get_param(7_999)
        .expect("invalid restore must not delete the live canonical governance object");
    assert_eq!(after.key, live_snapshot.key);
    assert_eq!(after.value, live_snapshot.value);
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "invalid restore must preserve the canonical governance registry binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "invalid restore must preserve the prior deterministic root instead of deleting the live canonical governance slot"
    );
}

#[test]
fn restore_gov_param_rejects_unknown_snapshot_without_deleting_live_canonical_param() {
    let mut state = StateStore::new();
    state
        .set_gov_param(98_210, 7_999, "emergency_pause".into(), "true".into())
        .expect("canonical emergency_pause must be set first");
    let live_snapshot = state
        .get_param(7_999)
        .expect("live canonical emergency_pause object must exist");
    let root_before = state.state_root();

    state.restore_gov_param(
        7_999,
        Some(GovParamObject {
            key_id: 7_999,
            key: "emergency_pause_alias".to_string(),
            value: "false".to_string(),
            version: live_snapshot.version + 1,
        }),
    );

    let after = state
        .get_param(7_999)
        .expect("unknown-key restore must not delete the live canonical governance object");
    assert_eq!(after.key, live_snapshot.key);
    assert_eq!(after.value, live_snapshot.value);
    assert_eq!(
        state.gov_param_string("emergency_pause"),
        Some("true".to_string()),
        "unknown-key restore must preserve the canonical governance registry binding"
    );
    assert_eq!(
        state.state_root(),
        root_before,
        "unknown-key restore must preserve the prior deterministic root instead of deleting the live canonical governance slot"
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

    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_011,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_success_bounty",
        PendingGovParamUpdate {
            key_id: 7_012,
            key: "challenge_success_bounty".to_string(),
            value: "12".to_string(),
            activate_at_height: 1_020,
        },
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
fn restore_pending_gov_update_non_canonical_metadata_fails_closed_without_aliasing_snapshot_root() {
    let mut state = StateStore::new();
    let baseline_root = state.state_root();

    state.restore_pending_gov_update(
        "challenge_min_bond",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "challenge_min_bond ".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert!(
        state.pending_gov_update("challenge_min_bond").is_none(),
        "non-canonical restore metadata must clear the requested slot instead of staging a whitespace-variant pending key"
    );
    assert!(
        state.pending_gov_update("challenge_min_bond ").is_none(),
        "non-canonical restore metadata must not materialize a foreign pending entry under the malformed snapshot key"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "non-canonical pending governance metadata must fail closed without perturbing the deterministic root"
    );
    assert_eq!(
        state.state_root(),
        baseline_root,
        "repeated reads after rejecting malformed pending governance metadata should deterministically reuse the unchanged cached root"
    );
}

#[test]
fn insertion_order_of_pending_gov_updates_keeps_state_root_deterministic() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    restore_pending_gov_update_with_base(
        &mut state_a,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_a,
        "min_worker_stake",
        PendingGovParamUpdate {
            key_id: 7_202,
            key: "min_worker_stake".to_string(),
            value: "9000".to_string(),
            activate_at_height: 1_040,
        },
    );

    restore_pending_gov_update_with_base(
        &mut state_b,
        "min_worker_stake",
        PendingGovParamUpdate {
            key_id: 7_202,
            key: "min_worker_stake".to_string(),
            value: "9000".to_string(),
            activate_at_height: 1_040,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
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

    restore_pending_gov_update_with_base(
        &mut state,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_301,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state,
        "max_block_ms",
        PendingGovParamUpdate {
            key_id: 7_302,
            key: "max_block_ms".to_string(),
            value: "500".to_string(),
            activate_at_height: 33,
        },
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
    install_pending_gov_base(&mut expected, 7_302, "max_block_ms");
    restore_pending_gov_update_with_base(
        &mut expected,
        "challenge_min_bond",
        canonical_other_snapshot,
    );

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

    restore_pending_gov_update_with_base(
        &mut state_a,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_202,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance key_id must contribute to state_root so logically distinct staged updates do not hash the same"
    );

    let mut rewound = StateStore::new();
    restore_pending_gov_update_with_base(
        &mut rewound,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );

    assert_eq!(
        rewound.state_root(),
        root_a,
        "restoring the original pending governance key_id should rewind the deterministic root exactly"
    );
}

#[test]
fn pending_gov_update_activation_height_changes_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    restore_pending_gov_update_with_base(
        &mut state_a,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_021,
        },
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "pending governance activation height must contribute to state_root so distinct timelock schedules do not hash the same"
    );

    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
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

    restore_pending_gov_update_with_base(
        &mut state_a,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6000".to_string(),
            activate_at_height: 1_020,
        },
    );
    restore_pending_gov_update_with_base(
        &mut state_b,
        "challenge_min_bond",
        PendingGovParamUpdate {
            key_id: 7_201,
            key: "challenge_min_bond".to_string(),
            value: "6500".to_string(),
            activate_at_height: 1_020,
        },
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
fn checkpoint_evidence_surface_requires_canonical_state_root_and_hash_hex() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "canonical checkpoint/WAL evidence surfaces should be recognized as audit-ready"
    );

    let mut bad_checkpoint = checkpoint.clone();
    bad_checkpoint.state_root_hex = "not-hex".into();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &wal),
        "checkpoint state_root_hex must be canonical hex for audit evidence surfaces"
    );

    let mut bad_wal = wal.clone();
    bad_wal.state_root_hex = "still-not-hex".into();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &bad_wal),
        "WAL state_root_hex must be canonical hex for audit evidence surfaces"
    );

    let mut mismatched_checkpoint_root = checkpoint.clone();
    mismatched_checkpoint_root.state_root_hex = "cd".repeat(32);
    assert!(
        !checkpoint_evidence_surface_is_canonical(&mismatched_checkpoint_root, &wal),
        "checkpoint state_root_hex must match the evidenced WAL state root for audit-ready checkpoint surfaces"
    );

    let mut mismatched_checkpoint_wal_hash = checkpoint.clone();
    mismatched_checkpoint_wal_hash.wal_entry_hash_hex = "ef".repeat(32);
    assert!(
        !checkpoint_evidence_surface_is_canonical(&mismatched_checkpoint_wal_hash, &wal),
        "checkpoint wal_entry_hash_hex must bind to the exact WAL content hash for audit-ready checkpoint surfaces"
    );

    let mut uppercase_checkpoint_wal_hash = checkpoint.clone();
    uppercase_checkpoint_wal_hash.wal_entry_hash_hex = uppercase_checkpoint_wal_hash
        .wal_entry_hash_hex
        .to_uppercase();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&uppercase_checkpoint_wal_hash, &wal),
        "checkpoint wal_entry_hash_hex must stay lowercase canonical hex so audit surfaces do not accept mixed-case WAL digest encodings"
    );

    let mut short_checkpoint_wal_hash = checkpoint.clone();
    short_checkpoint_wal_hash.wal_entry_hash_hex = "ab".repeat(31);
    assert!(
        !checkpoint_evidence_surface_is_canonical(&short_checkpoint_wal_hash, &wal),
        "checkpoint wal_entry_hash_hex must stay 32-byte canonical hex so audit surfaces do not accept truncated WAL digest encodings"
    );

    let mut uppercase_checkpoint = checkpoint.clone();
    uppercase_checkpoint.state_root_hex = uppercase_checkpoint.state_root_hex.to_uppercase();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&uppercase_checkpoint, &wal),
        "checkpoint state_root_hex must stay lowercase canonical hex so audit surfaces do not accept mixed-case digest encodings"
    );

    let mut mismatched_height_checkpoint = checkpoint.clone();
    mismatched_height_checkpoint.height = wal.height + 1;
    assert!(
        !checkpoint_evidence_surface_is_canonical(&mismatched_height_checkpoint, &wal),
        "checkpoint height must bind to the exact WAL height so audit evidence surfaces cannot replay canonical hashes across different checkpoint slots"
    );

    let mut zero_height_checkpoint = checkpoint.clone();
    zero_height_checkpoint.height = 0;
    let mut zero_height_wal = wal.clone();
    zero_height_wal.height = 0;
    zero_height_checkpoint.wal_entry_hash_hex = zero_height_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&zero_height_checkpoint, &zero_height_wal),
        "checkpoint evidence surfaces must reject height zero so audit-ready checkpoint proofs cannot treat non-genesis metadata slots as valid state-root checkpoints"
    );

    let mut uncommitted_wal = wal.clone();
    uncommitted_wal.committed = false;
    let mut uncommitted_checkpoint = checkpoint.clone();
    uncommitted_checkpoint.wal_entry_hash_hex = uncommitted_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&uncommitted_checkpoint, &uncommitted_wal),
        "checkpoint evidence surfaces must reject uncommitted WAL entries so audit-ready checkpoint proofs cannot bind to speculative state-root snapshots"
    );

    let mut blank_proposal_hash_wal = wal.clone();
    blank_proposal_hash_wal.proposal_hash = "".into();
    let mut blank_proposal_hash_checkpoint = checkpoint.clone();
    blank_proposal_hash_checkpoint.wal_entry_hash_hex = blank_proposal_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(&blank_proposal_hash_checkpoint, &blank_proposal_hash_wal),
        "WAL proposal_hash must be a non-empty canonical token so checkpoint evidence surfaces cannot claim audit-ready provenance with blank proposal identity"
    );

    let mut whitespace_proposal_hash_wal = wal.clone();
    whitespace_proposal_hash_wal.proposal_hash = " proposal-1 ".into();
    let mut whitespace_proposal_hash_checkpoint = checkpoint.clone();
    whitespace_proposal_hash_checkpoint.wal_entry_hash_hex =
        whitespace_proposal_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &whitespace_proposal_hash_checkpoint,
            &whitespace_proposal_hash_wal,
        ),
        "checkpoint evidence surfaces must reject edge-whitespace WAL proposal_hash values so audit-ready provenance cannot smuggle trim-sensitive proposal identities into canonical checkpoint bindings"
    );

    let mut forged_genesis_prev_hash_wal = wal.clone();
    forged_genesis_prev_hash_wal.prev_hash_hex = Some("01".repeat(32));
    let mut forged_genesis_prev_hash_checkpoint = checkpoint.clone();
    forged_genesis_prev_hash_checkpoint.wal_entry_hash_hex =
        forged_genesis_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &forged_genesis_prev_hash_checkpoint,
            &forged_genesis_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject genesis WAL metadata with a forged prev_hash_hex so audit-ready state-root proofs cannot smuggle a fake predecessor link into height-1 checkpoints"
    );

    let mut missing_prev_hash_wal = wal.clone();
    missing_prev_hash_wal.height = 2;
    missing_prev_hash_wal.prev_hash_hex = None;
    let mut missing_prev_hash_checkpoint = checkpoint.clone();
    missing_prev_hash_checkpoint.height = 2;
    missing_prev_hash_checkpoint.wal_entry_hash_hex = missing_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &missing_prev_hash_checkpoint,
            &missing_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject non-genesis WAL metadata without prev_hash_hex so audit-ready state-root proofs cannot omit the predecessor link for height-2+ checkpoints"
    );

    let mut blank_prev_hash_wal = wal.clone();
    blank_prev_hash_wal.height = 2;
    blank_prev_hash_wal.prev_hash_hex = Some(String::new());
    let mut blank_prev_hash_checkpoint = checkpoint.clone();
    blank_prev_hash_checkpoint.height = 2;
    blank_prev_hash_checkpoint.wal_entry_hash_hex = blank_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &blank_prev_hash_checkpoint,
            &blank_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject blank prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links cannot smuggle an empty digest surface into otherwise linked checkpoints"
    );

    let mut uppercase_prev_hash_wal = wal.clone();
    uppercase_prev_hash_wal.height = 2;
    uppercase_prev_hash_wal.prev_hash_hex = Some("ab".repeat(32).to_uppercase());
    let mut uppercase_prev_hash_checkpoint = checkpoint.clone();
    uppercase_prev_hash_checkpoint.height = 2;
    uppercase_prev_hash_checkpoint.wal_entry_hash_hex = uppercase_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &uppercase_prev_hash_checkpoint,
            &uppercase_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject mixed-case prev_hash_hex on non-genesis WAL metadata so audit-ready state-root proofs cannot encode predecessor links with non-canonical digest surfaces"
    );

    let mut whitespace_prev_hash_wal = wal.clone();
    whitespace_prev_hash_wal.height = 2;
    whitespace_prev_hash_wal.prev_hash_hex = Some(format!(" {} ", "ab".repeat(32)));
    let mut whitespace_prev_hash_checkpoint = checkpoint.clone();
    whitespace_prev_hash_checkpoint.height = 2;
    whitespace_prev_hash_checkpoint.wal_entry_hash_hex = whitespace_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &whitespace_prev_hash_checkpoint,
            &whitespace_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject edge-whitespace prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links cannot hide non-canonical digest framing behind trim-sensitive surfaces"
    );

    let mut zero_width_prev_hash_wal = wal.clone();
    zero_width_prev_hash_wal.height = 2;
    zero_width_prev_hash_wal.prev_hash_hex = Some(format!("{}\u{200b}", "ab".repeat(32)));
    let mut zero_width_prev_hash_checkpoint = checkpoint.clone();
    zero_width_prev_hash_checkpoint.height = 2;
    zero_width_prev_hash_checkpoint.wal_entry_hash_hex = zero_width_prev_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &zero_width_prev_hash_checkpoint,
            &zero_width_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject zero-width prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links cannot hide layout drift behind visually identical digest surfaces"
    );

    let mut non_ascii_proposal_hash_wal = wal.clone();
    non_ascii_proposal_hash_wal.proposal_hash = "proposal-owl".into();
    let mut non_ascii_proposal_hash_checkpoint = checkpoint.clone();
    non_ascii_proposal_hash_checkpoint.wal_entry_hash_hex =
        non_ascii_proposal_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &non_ascii_proposal_hash_checkpoint,
            &non_ascii_proposal_hash_wal,
        ),
        "checkpoint evidence surfaces must reject non-ascii WAL proposal_hash values so verifier sidecars cannot publish DA-linked checkpoint provenance with locale-dependent proposal identities"
    );

    let mut overlong_proposal_hash_wal = wal.clone();
    overlong_proposal_hash_wal.proposal_hash = "p".repeat(257);
    let mut overlong_proposal_hash_checkpoint = checkpoint.clone();
    overlong_proposal_hash_checkpoint.wal_entry_hash_hex =
        overlong_proposal_hash_wal.content_hash_hex();
    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &overlong_proposal_hash_checkpoint,
            &overlong_proposal_hash_wal,
        ),
        "checkpoint evidence surfaces must reject overlong WAL proposal_hash values so DA/light-verifier sidecars cannot anchor checkpoint evidence to unbounded proposal identity surfaces"
    );
}

#[test]
fn checkpoint_commitment_and_wal_content_hash_length_frame_adjacent_fields() {
    let wal_a = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "ab".into(),
        committed: true,
        state_root_hex: "c".repeat(64),
        prev_hash_hex: Some("de".repeat(32)),
    };
    let wal_b = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "a".into(),
        state_root_hex: format!("b{}", "c".repeat(63)),
        ..wal_a.clone()
    };

    assert_ne!(
        wal_a.content_hash_hex(),
        wal_b.content_hash_hex(),
        "wal content_hash_hex must length-frame proposal_hash and state_root_hex so adjacent field-boundary collisions cannot hash identically"
    );

    let checkpoint_a = CheckpointMeta {
        height: 9,
        state_root_hex: "ab".repeat(32),
        wal_entry_hash_hex: "cd".repeat(32),
    };
    let checkpoint_b = CheckpointMeta {
        height: 9,
        state_root_hex: format!("{}c", "ab".repeat(31)),
        wal_entry_hash_hex: format!("d{}", "cd".repeat(31)),
    };

    assert_ne!(
        checkpoint_a.commitment_hex(),
        checkpoint_b.commitment_hex(),
        "checkpoint commitment_hex must length-frame state_root_hex and wal_entry_hash_hex so adjacent field-boundary collisions cannot hash identically"
    );
}

#[test]
fn wal_content_hash_committed_bit_must_affect_checkpoint_evidence_digest() {
    let committed = WalMeta {
        height: 12,
        round: 3,
        proposal_hash: "proposal-12".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("01".repeat(32)),
    };
    let mut uncommitted = committed.clone();
    uncommitted.committed = false;

    assert_ne!(
        committed.content_hash_hex(),
        uncommitted.content_hash_hex(),
        "WAL checkpoint evidence digest must include the committed bit so proof-facing metadata cannot hash the same across committed and speculative entries"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_wal_proposal_hash_with_forbidden_layout() {
    let wal = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "proposal-9 ".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal_hash values with forbidden layout so audit-ready checkpoint proofs cannot rely on whitespace-variant proposal identifiers"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal),
        None,
        "DA/light-verifier summaries must fail closed when WAL proposal_hash carries forbidden layout even if the tuple still hashes to canonical lowercase hex"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_zero_width_proposal_hash_surface() {
    let wal = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: format!("proposal-9{}", '\u{200b}'),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject zero-width WAL proposal_hash values so audit-ready checkpoint proofs cannot rely on visually identical but non-canonical proposal identities"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal),
        None,
        "DA/light-verifier summaries must fail closed when WAL proposal_hash carries zero-width layout drift even if the tuple still hashes to canonical lowercase hex"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_mixed_case_non_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "proposal-7".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should expose a DA/light-verifier summary"
    );

    let mut mixed_case_prev_hash_wal = wal.clone();
    mixed_case_prev_hash_wal.prev_hash_hex = Some("cd".repeat(32).to_uppercase());
    let mixed_case_checkpoint = CheckpointMeta {
        height: mixed_case_prev_hash_wal.height,
        state_root_hex: mixed_case_prev_hash_wal.state_root_hex.clone(),
        wal_entry_hash_hex: mixed_case_prev_hash_wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&mixed_case_checkpoint, &mixed_case_prev_hash_wal),
        "checkpoint evidence surfaces must reject mixed-case prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links stay canonical"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(&mixed_case_checkpoint, &mixed_case_prev_hash_wal),
        None,
        "DA/light-verifier summaries must fail closed when non-genesis prev_hash_hex is encoded with mixed-case digest surfaces"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_zero_width_non_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "proposal-7".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should expose a DA/light-verifier summary"
    );

    let mut zero_width_prev_hash_wal = wal.clone();
    zero_width_prev_hash_wal.prev_hash_hex = Some(format!("{}\u{200b}", "cd".repeat(32)));
    let zero_width_prev_hash_checkpoint = CheckpointMeta {
        height: zero_width_prev_hash_wal.height,
        state_root_hex: zero_width_prev_hash_wal.state_root_hex.clone(),
        wal_entry_hash_hex: zero_width_prev_hash_wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &zero_width_prev_hash_checkpoint,
            &zero_width_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject zero-width prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links stay byte-canonical"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(
            &zero_width_prev_hash_checkpoint,
            &zero_width_prev_hash_wal,
        ),
        None,
        "DA/light-verifier summaries must fail closed when non-genesis prev_hash_hex carries zero-width layout drift"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_carriage_return_non_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "proposal-7".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should expose a DA/light-verifier summary"
    );

    let mut carriage_return_prev_hash_wal = wal.clone();
    carriage_return_prev_hash_wal.prev_hash_hex = Some(format!("{}\r", "cd".repeat(32)));
    let carriage_return_prev_hash_checkpoint = CheckpointMeta {
        height: carriage_return_prev_hash_wal.height,
        state_root_hex: carriage_return_prev_hash_wal.state_root_hex.clone(),
        wal_entry_hash_hex: carriage_return_prev_hash_wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(
            &carriage_return_prev_hash_checkpoint,
            &carriage_return_prev_hash_wal,
        ),
        "checkpoint evidence surfaces must reject carriage-return prev_hash_hex on non-genesis WAL metadata so audit-ready predecessor links stay byte-canonical"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(
            &carriage_return_prev_hash_checkpoint,
            &carriage_return_prev_hash_wal,
        ),
        None,
        "DA/light-verifier summaries must fail closed when non-genesis prev_hash_hex carries carriage-return control drift"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_forged_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-genesis".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical genesis checkpoint/WAL evidence should expose a DA/light-verifier summary"
    );

    let mut forged_prev_hash_wal = wal.clone();
    forged_prev_hash_wal.prev_hash_hex = Some("01".repeat(32));
    let forged_prev_hash_checkpoint = CheckpointMeta {
        height: forged_prev_hash_wal.height,
        state_root_hex: forged_prev_hash_wal.state_root_hex.clone(),
        wal_entry_hash_hex: forged_prev_hash_wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&forged_prev_hash_checkpoint, &forged_prev_hash_wal),
        "checkpoint evidence surfaces must reject forged genesis prev_hash_hex so height-1 audit proofs cannot smuggle a predecessor link"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(&forged_prev_hash_checkpoint, &forged_prev_hash_wal),
        None,
        "DA/light-verifier summaries must fail closed when genesis WAL metadata forges prev_hash_hex"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_rejects_blank_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-genesis".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical genesis checkpoint/WAL evidence should expose a DA/light-verifier summary"
    );

    let mut blank_prev_hash_wal = wal.clone();
    blank_prev_hash_wal.prev_hash_hex = Some(String::new());
    let blank_prev_hash_checkpoint = CheckpointMeta {
        height: blank_prev_hash_wal.height,
        state_root_hex: blank_prev_hash_wal.state_root_hex.clone(),
        wal_entry_hash_hex: blank_prev_hash_wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&blank_prev_hash_checkpoint, &blank_prev_hash_wal),
        "checkpoint evidence surfaces must reject blank genesis prev_hash_hex so height-1 audit proofs cannot smuggle an empty predecessor surface"
    );
    assert_eq!(
        checkpoint_da_light_verifier_summary(&blank_prev_hash_checkpoint, &blank_prev_hash_wal),
        None,
        "DA/light-verifier summaries must fail closed when genesis WAL metadata encodes blank prev_hash_hex instead of canonical none"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_exposes_canonical_surface_fields() {
    let wal = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "proposal-7".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
        .expect("canonical checkpoint/WAL evidence should expose a DA/light-verifier summary");

    assert!(summary.contains("da_light_surface=checkpoint-wal-v1"));
    assert!(summary.contains("light_verifier_surface=checkpoint-wal-v1"));
    assert!(summary.contains("da_anchor_total_bytes=96"));
    assert!(summary.contains(&format!(
        "da_state_commitment={}",
        checkpoint.state_root_hex
    )));
    assert!(summary.contains("da_state_commitment_kind=canonical-hex-32b"));
    assert!(summary.contains("da_state_commitment_bytes=32"));
    assert!(summary.contains(&format!(
        "da_checkpoint_commitment={}",
        checkpoint.commitment_hex()
    )));
    assert!(summary.contains("da_checkpoint_commitment_kind=canonical-hex-32b"));
    assert!(summary.contains("da_checkpoint_commitment_bytes=32"));
    assert!(summary.contains(&format!("da_wal_content_hash={}", wal.content_hash_hex())));
    assert!(summary.contains("da_wal_content_hash_kind=canonical-hex-32b"));
    assert!(summary.contains("da_wal_content_hash_bytes=32"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_height=true"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_round=true"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_proposal_hash=true"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_committed=true"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_state_root=true"));
    assert!(summary.contains("da_wal_content_hash_commits_wal_prev_hash=true"));
    assert!(summary.contains("checkpoint_binding_fields=height,state_root,wal_entry_hash"));
    assert!(summary.contains("checkpoint_tuple_order=height,state_root,wal_entry_hash"));
    assert!(summary.contains(
        "checkpoint_tuple_encoding=sha256(len-prefixed height-le-u64|state_root|wal_entry_hash)"
    ));
    assert!(summary.contains("checkpoint_commitment_fields=height,state_root,wal_entry_hash"));
    assert!(summary.contains("checkpoint_commitment_encoding=sha256(len-prefixed height-le-u64|state_root|wal_entry_hash)"));
    assert!(summary.contains("checkpoint_commitment_binding_kind=tuple-hash"));
    assert!(summary.contains("checkpoint_commitment_kind=canonical-hex-32b"));
    assert!(summary.contains("checkpoint_commitment_bytes=32"));
    assert!(summary.contains("checkpoint_height=7"));
    assert!(summary.contains("checkpoint_height_encoding=le-u64"));
    assert!(summary.contains("checkpoint_height_kind=bft-height-u64"));
    assert!(summary.contains("checkpoint_height_bytes=8"));
    assert!(summary.contains("checkpoint_height_boundary_kind=non-genesis"));
    assert!(summary.contains("checkpoint_state_root_kind=canonical-hex-32b"));
    assert!(summary.contains("checkpoint_state_root_bytes=32"));
    assert!(summary.contains("checkpoint_wal_entry_hash_kind=canonical-hex-32b"));
    assert!(summary.contains("checkpoint_wal_entry_hash_bytes=32"));
    assert!(summary.contains("checkpoint_height_matches_wal=true"));
    assert!(summary.contains("checkpoint_state_root_matches_wal=true"));
    assert!(summary.contains("checkpoint_wal_entry_hash_matches_wal=true"));
    assert!(summary.contains("checkpoint_surface_canonical=true"));
    assert!(summary.contains("checkpoint_wal_binding_kind=content-hash-equality"));
    assert!(summary.contains(
        "wal_content_hash_fields=height,round,proposal_hash,committed,state_root,prev_hash"
    ));
    assert!(summary
        .contains("wal_tuple_order=height,round,proposal_hash,committed,state_root,prev_hash"));
    assert!(summary.contains("wal_tuple_encoding=sha256(len-prefixed height-le-u64|round-le-u64|proposal_hash|committed-u8|state_root|prev_hash?)"));
    assert!(summary.contains("wal_height=7"));
    assert!(summary.contains("wal_height_encoding=le-u64"));
    assert!(summary.contains("wal_height_kind=bft-height-u64"));
    assert!(summary.contains("wal_height_bytes=8"));
    assert!(summary.contains("wal_round=3"));
    assert!(summary.contains("wal_round_encoding=le-u64"));
    assert!(summary.contains("wal_round_kind=bft-round-u64"));
    assert!(summary.contains("wal_round_bytes=8"));
    assert!(summary.contains("wal_state_root_kind=canonical-hex-32b"));
    assert!(summary.contains("wal_state_root_bytes=32"));
    assert!(summary.contains("wal_content_hash_kind=canonical-hex-32b"));
    assert!(summary.contains("wal_content_hash_bytes=32"));
    assert!(summary.contains("wal_content_hash_matches_checkpoint=true"));
    assert!(summary.contains("wal_content_hash_matches_checkpoint_wal_entry_hash=true"));
    assert!(summary.contains("wal_committed=true"));
    assert!(summary.contains("wal_committed_encoding=u8"));
    assert!(summary.contains("wal_committed_bytes=1"));
    assert!(summary.contains("wal_height_boundary_kind=non-genesis"));
    assert!(summary.contains(&format!("wal_prev_hash={}", "cd".repeat(32))));
    assert!(summary.contains("wal_prev_hash_present=true"));
    assert!(summary.contains("wal_prev_hash_required=true"));
    assert!(summary.contains("wal_prev_hash_kind=linked"));
    assert!(summary.contains("wal_prev_hash_matches_height_boundary=true"));
    assert!(summary.contains("wal_prev_hash_bytes=32"));
    assert!(summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
    assert!(summary.contains("wal_prev_hash_surface_canonical=true"));
    assert!(summary.contains("wal_linkage_kind=prev-hash-chain"));
    assert!(summary.contains("wal_proposal_hash=proposal-7"));
    assert!(summary.contains("wal_proposal_hash_present=true"));
    assert!(summary.contains("wal_proposal_hash_kind=opaque-ascii"));
    assert!(summary.contains("wal_proposal_hash_bytes=10"));
    assert!(summary.contains("wal_proposal_hash_surface_policy=ascii-trimmed-no-ws-control-max256"));
    assert!(summary.contains("wal_proposal_hash_surface_canonical=true"));
}

#[test]
fn checkpoint_da_light_verifier_summary_exposes_canonical_hex_encoding_metadata() {
    let wal = WalMeta {
        height: 7,
        round: 3,
        proposal_hash: "proposal-7".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
        .expect("canonical checkpoint/WAL evidence should expose canonical encoding metadata");

    assert!(summary.contains("da_state_commitment_encoding=hex-lower"));
    assert!(summary.contains("da_checkpoint_commitment_encoding=hex-lower"));
    assert!(summary.contains("da_wal_content_hash_encoding=hex-lower"));
    assert!(summary.contains("checkpoint_commitment_encoding=hex-lower"));
    assert!(summary.contains("checkpoint_state_root_encoding=hex-lower"));
    assert!(summary.contains("checkpoint_wal_entry_hash_encoding=hex-lower"));
    assert!(summary.contains("wal_state_root_encoding=hex-lower"));
    assert!(summary.contains("wal_content_hash_encoding=hex-lower"));
    assert!(summary.contains("wal_prev_hash_encoding=hex-lower-or-none"));
}

#[test]
fn checkpoint_da_light_verifier_summary_marks_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "genesis-proposal".into(),
        committed: true,
        state_root_hex: "ef".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
        .expect("genesis checkpoint/WAL evidence should still expose a DA/light-verifier summary");

    assert!(summary.contains("wal_height_boundary_kind=genesis"));
    assert!(summary.contains("wal_prev_hash=none"));
    assert!(summary.contains("checkpoint_height_boundary_kind=genesis"));
    assert!(summary.contains("wal_prev_hash_present=false"));
    assert!(summary.contains("wal_prev_hash_required=false"));
    assert!(summary.contains("wal_prev_hash_kind=genesis"));
    assert!(summary.contains("wal_prev_hash_matches_height_boundary=true"));
    assert!(summary.contains("wal_prev_hash_bytes=0"));
    assert!(summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
    assert!(summary.contains("wal_prev_hash_surface_canonical=true"));
    assert!(summary.contains("wal_linkage_kind=prev-hash-chain"));
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_forged_genesis_prev_hash_surface() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "genesis-proposal".into(),
        committed: true,
        state_root_hex: "ef".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some("01".repeat(32));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical genesis checkpoint/WAL evidence should summarize before the forged-prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "genesis WAL metadata with a forged prev_hash_hex must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_uppercase_checkpoint_state_root_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_checkpoint = checkpoint.clone();
    bad_checkpoint.state_root_hex = bad_checkpoint.state_root_hex.to_uppercase();

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical checkpoint/WAL evidence should stay audit-ready before the uppercase-checkpoint-state-root regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the uppercase-checkpoint-state-root regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &wal),
        "checkpoint evidence surfaces must reject uppercase checkpoint state_root_hex digests"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &wal).is_none(),
        "uppercase checkpoint state_root_hex surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_height_mismatch_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut mismatched_checkpoint = checkpoint.clone();
    mismatched_checkpoint.height += 1;

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the height-mismatch regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&mismatched_checkpoint, &wal).is_none(),
        "checkpoint/WAL height mismatches must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_zero_height_surface() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "genesis-proposal".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut zero_height_wal = wal.clone();
    zero_height_wal.height = 0;
    let zero_height_checkpoint = CheckpointMeta {
        height: 0,
        state_root_hex: zero_height_wal.state_root_hex.clone(),
        wal_entry_hash_hex: zero_height_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical genesis checkpoint/WAL evidence should summarize before the zero-height regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&zero_height_checkpoint, &zero_height_wal).is_none(),
        "height-zero checkpoint/WAL metadata must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_noncanonical_surfaces() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should produce a DA/light-verifier summary"
    );

    let mut bad_checkpoint = checkpoint.clone();
    bad_checkpoint.state_root_hex = "not-hex".into();
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &wal).is_none(),
        "noncanonical checkpoint state_root_hex must fail closed instead of emitting a DA/light-verifier summary"
    );

    let mut uppercase_wal_hash_checkpoint = checkpoint.clone();
    uppercase_wal_hash_checkpoint.wal_entry_hash_hex = uppercase_wal_hash_checkpoint
        .wal_entry_hash_hex
        .to_uppercase();
    assert!(
        checkpoint_da_light_verifier_summary(&uppercase_wal_hash_checkpoint, &wal).is_none(),
        "mixed-case checkpoint wal_entry_hash_hex must fail closed instead of emitting a DA/light-verifier summary"
    );

    let mut zero_width_wal_hash_checkpoint = checkpoint.clone();
    zero_width_wal_hash_checkpoint
        .wal_entry_hash_hex
        .push('\u{200b}');
    assert!(
        checkpoint_da_light_verifier_summary(&zero_width_wal_hash_checkpoint, &wal).is_none(),
        "zero-width checkpoint wal_entry_hash_hex surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal\n4".into();
    bad_checkpoint = checkpoint.clone();
    bad_checkpoint.wal_entry_hash_hex = bad_wal.content_hash_hex();
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "noncanonical WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_short_checkpoint_state_root_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should produce a DA/light-verifier summary before the short-state-root regression mutation"
    );

    let mut bad_checkpoint = checkpoint.clone();
    bad_checkpoint.state_root_hex = "ab".repeat(31);

    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &wal),
        "checkpoint evidence surfaces must reject checkpoint state_root_hex values that are not canonical 32-byte lowercase digests"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &wal).is_none(),
        "short checkpoint state_root_hex surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_uppercase_wal_state_root_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should produce a DA/light-verifier summary"
    );

    let mut bad_wal = wal.clone();
    bad_wal.state_root_hex = bad_wal.state_root_hex.to_uppercase();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "uppercase WAL state_root_hex must fail closed instead of emitting a DA/light-verifier summary even when checkpoint fields otherwise match the same mixed-case digest surface"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_uncommitted_wal_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.committed = false;
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the uncommitted-WAL regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "uncommitted WAL checkpoint evidence must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_whitespace_padded_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = " proposal-4 ".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the whitespace regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint audit surfaces must reject whitespace-padded WAL proposal identities so checkpoint proofs cannot hide non-canonical task linkage"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "whitespace-padded WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_blank_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the blank-proposal regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "blank WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_internal_whitespace_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal 4".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "canonical checkpoint/WAL evidence should stay audit-ready before the internal-whitespace regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the internal-whitespace regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject WAL proposal_hash values containing internal whitespace"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "internal-whitespace WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_zero_width_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal-4\u{200b}".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the zero-width regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject zero-width WAL proposal_hash values so audit-ready checkpoint proofs cannot rely on visually hidden proposal identity drift"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "zero-width WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_overlong_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "p".repeat(257);
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the overlong-proposal regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "overlong WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_noncanonical_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some("CD".repeat(32));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "noncanonical non-genesis WAL prev_hash_hex surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_short_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some("cd".repeat(31));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the short-prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex surfaces with non-32-byte canonical width must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_missing_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = None;
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the missing-prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL metadata without prev_hash_hex must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_blank_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(String::new());
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the blank-prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "blank non-genesis WAL prev_hash_hex must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_edge_whitespace_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(format!(" {} ", "cd".repeat(32)));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the edge-whitespace prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex with edge whitespace drift must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_control_char_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(format!("{}\n", "cd".repeat(32)));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the control-char prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex with control-character drift must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_carriage_return_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(format!("{}\r", "cd".repeat(32)));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical non-genesis checkpoint/WAL evidence should remain audit-ready before the carriage-return prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the carriage-return prev-hash regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "non-genesis WAL prev_hash_hex with carriage-return drift must fail canonical checkpoint evidence gating instead of remaining audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex with carriage-return drift must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_internal_whitespace_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(format!("{} {}", "cd".repeat(16), "cd".repeat(16)));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical non-genesis checkpoint/WAL evidence should remain audit-ready before the internal-whitespace prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the internal-whitespace prev-hash regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "non-genesis WAL prev_hash_hex with internal whitespace drift must fail canonical checkpoint evidence gating instead of remaining audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex with internal whitespace drift must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_zero_width_non_genesis_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.prev_hash_hex = Some(format!("{}\u{200b}", "cd".repeat(32)));
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical non-genesis checkpoint/WAL evidence should remain audit-ready before the zero-width prev-hash regression mutation"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical non-genesis checkpoint/WAL evidence should summarize before the zero-width prev-hash regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "non-genesis WAL prev_hash_hex with zero-width layout drift must fail canonical checkpoint evidence gating instead of remaining audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-genesis WAL prev_hash_hex with zero-width layout drift must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_evidence_surface_accepts_max_length_canonical_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "p".repeat(256),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "proposal_hash at the 256-byte canonical boundary should remain admissible for checkpoint/WAL audit surfaces"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_accepts_max_length_canonical_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "p".repeat(256),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
        .expect("max-length canonical WAL proposal_hash should remain audit-summary eligible");

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "proposal_hash at the 256-byte canonical boundary should remain admissible for checkpoint/WAL audit surfaces"
    );
    assert!(
        summary.contains("wal_proposal_hash_bytes=256"),
        "DA/light-verifier summary should report the exact max-length canonical WAL proposal_hash byte count"
    );
    assert!(
        summary.contains("wal_proposal_hash_present=true"),
        "DA/light-verifier summary should keep the max-length canonical WAL proposal surface explicitly marked present"
    );
    assert!(
        summary.contains("wal_proposal_hash_surface_canonical=true"),
        "DA/light-verifier summary should keep the WAL proposal surface marked canonical at the 256-byte boundary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_accepts_uppercase_ascii_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "PROPOSAL-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let summary = checkpoint_da_light_verifier_summary(&checkpoint, &wal)
        .expect("uppercase canonical ASCII WAL proposal_hash should remain audit-summary eligible");

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "uppercase ASCII proposal identities should remain admissible because WAL proposal_hash is an opaque canonical ASCII token rather than a lowercase hex digest"
    );
    assert!(
        summary.contains("wal_proposal_hash=PROPOSAL-4"),
        "DA/light-verifier summary should preserve uppercase canonical ASCII proposal identities verbatim"
    );
    assert!(
        summary.contains("wal_proposal_hash_kind=opaque-ascii"),
        "DA/light-verifier summary should continue classifying uppercase canonical proposal identities as opaque ASCII"
    );
    assert!(
        summary.contains("wal_proposal_hash_surface_canonical=true"),
        "DA/light-verifier summary should mark uppercase canonical ASCII proposal identities as canonical surfaces"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_non_ascii_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 4,
        round: 1,
        proposal_hash: "proposal-4".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal-4".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical checkpoint/WAL evidence should summarize before the regression mutation"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject non-ASCII WAL proposal_hash values so audit-ready checkpoint proofs cannot rely on non-canonical proposal identity encodings"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "non-ASCII WAL proposal_hash surfaces must fail closed instead of emitting a DA/light-verifier summary"
    );
}

#[test]
fn checkpoint_da_light_verifier_summary_fails_closed_on_control_char_wal_proposal_hash_surface() {
    let wal = WalMeta {
        height: 16,
        round: 2,
        proposal_hash: "proposal-16".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal-16\n".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "canonical WAL proposal_hash should keep checkpoint evidence audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "canonical WAL proposal_hash should still produce a DA/light-verifier summary"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject WAL proposal_hash values containing control characters"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "DA/light-verifier summaries must fail closed when WAL proposal_hash contains control characters"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_wal_proposal_hash_with_internal_tab() {
    let wal = WalMeta {
        height: 16,
        round: 2,
        proposal_hash: "proposal-16".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal\t16".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical WAL proposal_hash should keep checkpoint evidence audit-ready"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject WAL proposal_hash values containing internal tab whitespace"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "DA/light-verifier summaries must fail closed when WAL proposal_hash contains internal tab whitespace"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_wal_proposal_hash_with_carriage_return() {
    let wal = WalMeta {
        height: 16,
        round: 2,
        proposal_hash: "proposal-16".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let mut bad_wal = wal.clone();
    bad_wal.proposal_hash = "proposal-16\r".into();
    let bad_checkpoint = CheckpointMeta {
        height: bad_wal.height,
        state_root_hex: bad_wal.state_root_hex.clone(),
        wal_entry_hash_hex: bad_wal.content_hash_hex(),
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "sanity: canonical WAL proposal_hash should keep checkpoint evidence audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&checkpoint, &wal).is_some(),
        "sanity: canonical WAL proposal_hash should still produce a DA/light-verifier summary"
    );
    assert!(
        !checkpoint_evidence_surface_is_canonical(&bad_checkpoint, &bad_wal),
        "checkpoint evidence surfaces must reject WAL proposal_hash values containing carriage-return control characters"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&bad_checkpoint, &bad_wal).is_none(),
        "DA/light-verifier summaries must fail closed when WAL proposal_hash contains carriage-return control characters"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_noncanonical_non_genesis_prev_hash_even_when_hashes_match() {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("CD".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: 2,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject non-genesis WAL prev_hash_hex values that are not canonical lowercase digests even when state_root_hex and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_uppercase_wal_state_root_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32).to_uppercase(),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject uppercase WAL state_root_hex even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match, so audit-ready proofs require lowercase canonical digest surfaces end-to-end"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_uppercase_checkpoint_state_root_even_when_wal_matches() {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone().to_uppercase(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject uppercase checkpoint state_root_hex even when WAL state_root_hex and wal_entry_hash_hex otherwise match, so audit-ready proofs require lowercase canonical digest surfaces end-to-end"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_blank_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must fail closed when WAL proposal identity is blank even if checkpoint fields otherwise match"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_blank_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: String::new(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must fail closed when WAL proposal identity is blank even if checkpoint fields otherwise match"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_noncanonical_non_genesis_prev_hash_even_when_checkpoint_matches(
) {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("CD".repeat(32)),
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-genesis WAL prev_hash_hex values that are not canonical lowercase digests even when checkpoint fields otherwise match, so restart-time checkpoint proofs keep predecessor links audit-canonical"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_forged_genesis_prev_hash_even_when_checkpoint_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("01".repeat(32)),
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject forged genesis WAL prev_hash_hex values even when checkpoint fields otherwise match, so restart-time checkpoint proofs cannot smuggle a predecessor link into height-1 recovery evidence"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_proposal_hash_with_edge_whitespace() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: " proposal-1 ".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject WAL proposal identities with edge whitespace so restart-time checkpoint proofs stay canonical even when checkpoint fields otherwise match"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_overlong_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p".repeat(257),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject overlong WAL proposal identities so restart-time checkpoint proofs keep the same canonical audit-surface bound even when checkpoint fields otherwise match"
    );
}

#[test]
fn node_recovery_checkpoint_verification_accepts_max_length_canonical_proposal_hash() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p".repeat(256),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal.clone()]).unwrap();

    assert_eq!(
        got,
        Some(checkpoints[0].clone()),
        "node recovery should still accept WAL proposal identities exactly at the canonical 256-byte boundary so the fail-closed max-length guard does not regress into a false reject"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_control_char_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal\n1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject WAL proposal identities with embedded control characters so restart-time checkpoint proofs cannot hide layout drift inside otherwise matching checkpoint tuples"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_zero_width_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1\u{200b}".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject zero-width WAL proposal identities so restart-time checkpoint proofs cannot accept visually hidden layout drift even when checkpoint fields otherwise match"
    );
}

#[test]
fn node_recovery_checkpoint_verification_rejects_non_ascii_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1-π".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal]).unwrap();

    assert!(
        got.is_none(),
        "node recovery must reject non-ASCII WAL proposal identities so restart-time checkpoint proofs cannot bind to locale-sensitive proposal surfaces even when checkpoint fields otherwise match"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_overlong_proposal_hash_even_when_hashes_match() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p".repeat(257),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject overlong WAL proposal identities even when state_root_hex and wal_entry_hash_hex otherwise match canonical digests"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_non_ascii_proposal_hash_even_when_hashes_match() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject non-ASCII WAL proposal identities so audit-ready checkpoint proofs cannot depend on locale-sensitive proposal encodings even when hashes otherwise match"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_proposal_hash_with_embedded_newline_even_when_hashes_match()
{
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal\n1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal identities with embedded control/whitespace so audit-ready checkpoint proofs cannot hide layout drift inside otherwise matching hashes"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_proposal_hash_with_edge_whitespace_even_when_hashes_match() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: " proposal-1 ".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal identities with edge whitespace so audit-ready checkpoint proofs cannot hide slot identity drift behind trimmed hashes"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_proposal_hash_with_embedded_tab_even_when_hashes_match() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal\t1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal identities with embedded tab/control layout so audit-ready checkpoint proofs cannot hide proposal drift inside otherwise matching hashes"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_proposal_hash_with_embedded_carriage_return_even_when_hashes_match(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal\r1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal identities with embedded carriage-return control layout so audit-ready checkpoint proofs cannot hide proposal drift inside otherwise matching hashes"
    );
}

#[test]
fn checkpoint_evidence_surface_rejects_proposal_hash_with_zero_width_layout_drift_even_when_hashes_match(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: format!("proposal-1{}", '\u{200B}'),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    assert!(
        !checkpoint_evidence_surface_is_canonical(&checkpoint, &wal),
        "checkpoint evidence surfaces must reject WAL proposal identities with zero-width layout drift so audit-ready checkpoint proofs cannot hide visually identical proposal surfaces inside otherwise matching hashes"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_proposal_hash_with_edge_whitespace_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: " proposal-1 ".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must fail closed when WAL proposal identity carries edge whitespace even if checkpoint fields otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_overlong_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p".repeat(257),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must fail closed when WAL proposal identity exceeds the canonical audit surface bound even if checkpoint fields otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_non_ascii_proposal_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must fail closed when WAL proposal identity is non-ASCII even if checkpoint fields otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_noncanonical_checkpoint_state_root_even_when_wal_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.to_uppercase(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject noncanonical checkpoint state_root_hex even when the WAL entry and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_zero_width_checkpoint_state_root_even_when_wal_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: format!("{}\u{200B}", wal.state_root_hex),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject zero-width checkpoint state_root_hex surfaces even when the WAL entry and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_newline_checkpoint_state_root_even_when_wal_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: format!("{}\n", wal.state_root_hex),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject newline-variant checkpoint state_root_hex surfaces even when the WAL entry and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_noncanonical_checkpoint_wal_hash_even_when_state_root_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex().to_uppercase(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject noncanonical checkpoint wal_entry_hash_hex even when the state_root evidence otherwise matches"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_zero_width_checkpoint_wal_hash_even_when_state_root_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: format!("{}\u{200B}", wal.content_hash_hex()),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject zero-width checkpoint wal_entry_hash_hex surfaces even when the state_root evidence otherwise matches"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_newline_checkpoint_wal_hash_even_when_state_root_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: format!("{}\n", wal.content_hash_hex()),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject newline-variant checkpoint wal_entry_hash_hex surfaces even when the state_root evidence otherwise matches"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_non_ascii_checkpoint_wal_hash_even_when_state_root_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: format!("{}é", wal.content_hash_hex()),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject non-ASCII checkpoint wal_entry_hash_hex surfaces even when the state_root evidence otherwise matches"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_noncanonical_wal_prev_hash_surface() {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("CD".repeat(32)),
    };
    let checkpoints = vec![CheckpointMeta {
        height: 2,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject noncanonical WAL prev_hash_hex surfaces even when the checkpoint payload otherwise lines up"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_short_non_genesis_wal_prev_hash_even_when_checkpoint_matches(
) {
    let wal = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(31)),
    };
    let checkpoints = vec![CheckpointMeta {
        height: 2,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject short non-genesis WAL prev_hash_hex surfaces even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_forged_genesis_prev_hash_even_when_checkpoint_matches() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("01".repeat(32)),
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject forged genesis prev_hash_hex surfaces even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn checkpoint_audit_summary_rejects_forged_genesis_prev_hash_surface() {
    let canonical_checkpoint = CheckpointMeta {
        height: 1,
        state_root_hex: "ab".repeat(32),
        wal_entry_hash_hex: "cd".repeat(32),
    };
    let canonical_wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: canonical_checkpoint.state_root_hex.clone(),
        prev_hash_hex: None,
    };
    let canonical_checkpoint = CheckpointMeta {
        wal_entry_hash_hex: canonical_wal.content_hash_hex(),
        ..canonical_checkpoint
    };

    assert!(
        checkpoint_evidence_surface_is_canonical(&canonical_checkpoint, &canonical_wal),
        "sanity: canonical genesis checkpoint/WAL evidence should remain audit-ready"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&canonical_checkpoint, &canonical_wal).is_some(),
        "sanity: canonical genesis checkpoint/WAL evidence should emit an audit summary"
    );

    let forged_genesis_wal = WalMeta {
        prev_hash_hex: Some("01".repeat(32)),
        ..canonical_wal
    };
    assert!(
        !checkpoint_evidence_surface_is_canonical(&canonical_checkpoint, &forged_genesis_wal),
        "checkpoint audit surfaces must reject forged genesis prev_hash_hex so height-1 evidence stays fail-closed"
    );
    assert!(
        checkpoint_da_light_verifier_summary(&canonical_checkpoint, &forged_genesis_wal).is_none(),
        "light-verifier summaries must fail closed when genesis WAL evidence carries a predecessor hash"
    );
}

#[test]
fn wal_checkpoint_verification_falls_back_when_non_genesis_prev_hash_has_newline_drift() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "cd".repeat(32),
        prev_hash_hex: Some(format!("{}\n", h1)),
    };
    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: e1.state_root_hex.clone(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
    assert_eq!(
        got.map(|cp| cp.height),
        Some(1),
        "checkpoint recovery must fail closed back to the last unambiguous checkpoint when a non-genesis WAL prev_hash_hex carries newline drift instead of a canonical linked digest"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_noncanonical_wal_state_root_surface_even_when_checkpoint_matches(
) {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "AB".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject noncanonical WAL state_root_hex surfaces even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_wal_state_root_with_edge_whitespace_even_when_checkpoint_matches() {
    let canonical_root = "ab".repeat(32);
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: format!(" {} ", canonical_root),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject WAL state_root_hex surfaces with edge whitespace so audit-ready checkpoint proofs cannot hide layout drift behind otherwise matching checkpoint metadata"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_zero_width_wal_state_root_even_when_checkpoint_matches() {
    let canonical_root = "ab".repeat(32);
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: format!("{}\u{200B}", canonical_root),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject zero-width WAL state_root_hex surfaces even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match"
    );
}

#[test]
fn wal_checkpoint_verification_rejects_newline_wal_state_root_even_when_checkpoint_matches() {
    let canonical_root = "ab".repeat(32);
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: format!("{}\n", canonical_root),
        prev_hash_hex: None,
    };
    let checkpoints = vec![CheckpointMeta {
        height: 1,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    }];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal]).unwrap();
    assert!(
        got.is_none(),
        "checkpoint recovery must reject newline-tailed WAL state_root_hex surfaces even when checkpoint state_root_hex and wal_entry_hash_hex otherwise match"
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

#[test]
fn checkpoint_and_wal_evidence_summaries_expose_canonical_hex_and_boundary_fields() {
    let wal = WalMeta {
        height: 2,
        round: 5,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32)),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let checkpoint_summary = checkpoint.evidence_summary();
    assert!(checkpoint_summary.contains("checkpoint_state_root_source=checkpoint.state_root_hex"));
    assert!(checkpoint_summary.contains(&format!(
        "checkpoint_state_root={}",
        checkpoint.state_root_hex
    )));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_source=checkpoint.wal_entry_hash_hex"));
    assert!(checkpoint_summary.contains(&format!(
        "checkpoint_wal_entry_hash={}",
        checkpoint.wal_entry_hash_hex
    )));
    assert!(checkpoint_summary.contains("checkpoint_commitment_source=checkpoint.commitment_hex"));
    assert!(checkpoint_summary.contains(&format!(
        "checkpoint_commitment={}",
        checkpoint.commitment_hex()
    )));
    assert!(checkpoint_summary.contains("checkpoint_evidence_surface=checkpoint-v1"));
    assert!(checkpoint_summary.contains("checkpoint_evidence_surface=checkpoint-v1"));
    assert!(checkpoint_summary.contains("checkpoint_height_boundary_kind=non-genesis"));
    assert!(checkpoint_summary.contains("checkpoint_state_root_kind=canonical-hex-32b"));
    assert!(checkpoint_summary.contains("checkpoint_state_root_encoding=hex-lower"));
    assert!(checkpoint_summary.contains("checkpoint_state_root_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_kind=canonical-hex-32b"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_encoding=hex-lower"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_commitment_kind=canonical-hex-32b"));
    assert!(checkpoint_summary.contains("checkpoint_commitment_encoding=hex-lower"));
    assert!(checkpoint_summary.contains("checkpoint_commitment_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_surface_canonical=true"));

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_evidence_surface=wal-v1"));
    assert!(wal_summary.contains("wal_state_root_kind=canonical-hex-32b"));
    assert!(wal_summary.contains("wal_state_root_encoding=hex-lower"));
    assert!(wal_summary.contains("wal_state_root_bytes=32"));
    assert!(wal_summary.contains("wal_proposal_hash_surface_policy=ascii-trimmed-no-ws-control-max256"));
    assert!(wal_summary.contains("wal_committed_encoding=u8"));
    assert!(wal_summary.contains("wal_prev_hash_present=true"));
    assert!(wal_summary.contains("wal_prev_hash_kind=linked"));
    assert!(wal_summary.contains("wal_prev_hash_bytes=32"));
    assert!(wal_summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
    assert!(wal_summary.contains("wal_prev_hash_encoding=hex-lower-or-none"));
    assert!(wal_summary.contains("wal_content_hash_kind=canonical-hex-32b"));
    assert!(wal_summary.contains("wal_content_hash_encoding=hex-lower"));
    assert!(wal_summary.contains("wal_content_hash_bytes=32"));
}

#[test]
fn genesis_checkpoint_and_wal_evidence_summaries_mark_boundary_and_prev_hash_absence() {
    let wal = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-genesis".into(),
        committed: true,
        state_root_hex: "12".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let checkpoint_summary = checkpoint.evidence_summary();
    assert!(checkpoint_summary.contains("checkpoint_height_boundary_kind=genesis"));
    assert!(checkpoint_summary.contains("checkpoint_height=1"));
    assert!(checkpoint_summary.contains("checkpoint_state_root_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_commitment_bytes=32"));
    assert!(checkpoint_summary.contains("checkpoint_surface_canonical=true"));

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_prev_hash=none"));
    assert!(wal_summary.contains("wal_prev_hash_present=false"));
    assert!(wal_summary.contains("wal_prev_hash_kind=genesis"));
    assert!(wal_summary.contains("wal_prev_hash_bytes=0"));
    assert!(wal_summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
    assert!(wal_summary.contains("wal_prev_hash_encoding=hex-lower-or-none"));
    assert!(wal_summary.contains("wal_content_hash_kind=canonical-hex-32b"));
    assert!(wal_summary.contains("wal_content_hash_bytes=32"));
}

#[test]
fn wal_evidence_summary_exposes_round_height_and_proposal_hash_surface_fields() {
    let wal = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "PROPOSAL-09/A".into(),
        committed: true,
        state_root_hex: "34".repeat(32),
        prev_hash_hex: Some("56".repeat(32)),
    };

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_evidence_surface=wal-v1"));
    assert!(wal_summary.contains("wal_height=9"));
    assert!(wal_summary.contains("wal_height_encoding=le-u64"));
    assert!(wal_summary.contains("wal_height_bytes=8"));
    assert!(wal_summary.contains("wal_round=4"));
    assert!(wal_summary.contains("wal_round_encoding=le-u64"));
    assert!(wal_summary.contains("wal_round_bytes=8"));
    assert!(wal_summary.contains("wal_proposal_hash=PROPOSAL-09/A"));
    assert!(wal_summary.contains("wal_proposal_hash_present=true"));
    assert!(wal_summary.contains("wal_proposal_hash_kind=opaque-ascii"));
    assert!(wal_summary.contains("wal_proposal_hash_bytes=13"));
    assert!(wal_summary.contains("wal_proposal_hash_surface_policy=ascii-trimmed-no-ws-control-max256"));
    assert!(wal_summary.contains("wal_prev_hash_present=true"));
    assert!(wal_summary.contains("wal_prev_hash_kind=linked"));
    assert!(wal_summary.contains("wal_committed=true"));
    assert!(wal_summary.contains(&format!("wal_entry_hash={}", wal.content_hash_hex())));
}

#[test]
fn zero_height_checkpoint_and_wal_evidence_summaries_fail_closed_as_noncanonical() {
    let wal = WalMeta {
        height: 0,
        round: 0,
        proposal_hash: "proposal-zero-height".into(),
        committed: true,
        state_root_hex: "34".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.clone(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let checkpoint_summary = checkpoint.evidence_summary();
    assert!(checkpoint_summary.contains("checkpoint_height=0"));
    assert!(checkpoint_summary.contains("checkpoint_height_boundary_kind=non-genesis"));
    assert!(
        checkpoint_summary.contains("checkpoint_surface_canonical=false"),
        "height-zero checkpoint summaries must fail closed instead of advertising canonical audit evidence"
    );

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_height=0"));
    assert!(wal_summary.contains("wal_prev_hash=none"));
    assert!(wal_summary.contains("wal_prev_hash_present=false"));
    assert!(
        wal_summary.contains("wal_surface_canonical=false"),
        "height-zero WAL summaries must fail closed instead of advertising canonical audit evidence"
    );
}

#[test]
fn wal_evidence_summary_marks_overlong_proposal_hash_surface_noncanonical() {
    let wal = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "p".repeat(257),
        committed: true,
        state_root_hex: "34".repeat(32),
        prev_hash_hex: Some("56".repeat(32)),
    };

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_proposal_hash_present=true"));
    assert!(wal_summary.contains("wal_proposal_hash_bytes=257"));
    assert!(
        wal_summary.contains("wal_surface_canonical=false"),
        "wal evidence summary must fail closed when proposal_hash exceeds the canonical 256-byte audit surface bound"
    );
}

#[test]
fn wal_evidence_summary_marks_whitespace_only_proposal_hash_surface_absent_and_noncanonical() {
    let wal = WalMeta {
        height: 9,
        round: 4,
        proposal_hash: "   ".into(),
        committed: true,
        state_root_hex: "34".repeat(32),
        prev_hash_hex: Some("56".repeat(32)),
    };

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_proposal_hash=   "));
    assert!(wal_summary.contains("wal_proposal_hash_present=false"));
    assert!(wal_summary.contains("wal_proposal_hash_bytes=3"));
    assert!(
        wal_summary.contains("wal_surface_canonical=false"),
        "wal evidence summary must not advertise whitespace-only proposal_hash surfaces as present when the audit surface is noncanonical"
    );
}

#[test]
fn checkpoint_and_wal_evidence_summaries_mark_noncanonical_surfaces_false() {
    let wal = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: Some("cd".repeat(32).to_uppercase()),
    };
    let checkpoint = CheckpointMeta {
        height: wal.height,
        state_root_hex: wal.state_root_hex.to_uppercase(),
        wal_entry_hash_hex: wal.content_hash_hex(),
    };

    let checkpoint_summary = checkpoint.evidence_summary();
    assert!(checkpoint_summary.contains("checkpoint_surface_canonical=false"));
    assert!(checkpoint_summary.contains("checkpoint_height_boundary_kind=non-genesis"));
    assert!(checkpoint_summary.contains("checkpoint_state_root_encoding=hex-lower"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_encoding=hex-lower"));

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_surface_canonical=false"));
    assert!(wal_summary.contains("wal_prev_hash_present=true"));
    assert!(wal_summary.contains("wal_prev_hash_kind=linked"));
    assert!(wal_summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
}

#[test]
fn wal_evidence_summary_rejects_short_ascii_state_root_surface() {
    let wal = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "proposal-2".into(),
        committed: true,
        state_root_hex: "state-root-2".into(),
        prev_hash_hex: Some("cd".repeat(32)),
    };

    let wal_summary = wal.evidence_summary();
    assert!(wal_summary.contains("wal_state_root=state-root-2"));
    assert!(wal_summary.contains("wal_state_root_kind=canonical-hex-32b"));
    assert!(wal_summary.contains("wal_state_root_encoding=hex-lower"));
    assert!(
        wal_summary.contains("wal_surface_canonical=false"),
        "wal evidence summary must fail closed when state_root_hex is printable ascii but not a canonical 32-byte lower-hex digest"
    );
}

#[test]
fn checkpoint_evidence_summary_marks_blank_digest_surfaces_noncanonical() {
    let checkpoint = CheckpointMeta {
        height: 2,
        state_root_hex: String::new(),
        wal_entry_hash_hex: String::new(),
    };

    let checkpoint_summary = checkpoint.evidence_summary();
    assert!(checkpoint_summary.contains("checkpoint_state_root="));
    assert!(checkpoint_summary.contains("checkpoint_state_root_bytes=0"));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash="));
    assert!(checkpoint_summary.contains("checkpoint_wal_entry_hash_bytes=0"));
    assert!(
        checkpoint_summary.contains("checkpoint_surface_canonical=false"),
        "checkpoint evidence summary must fail closed when state_root_hex or wal_entry_hash_hex is blank so restart-time evidence cannot advertise missing digest surfaces as canonical"
    );
}

#[test]
fn wal_checkpoint_conflicting_same_height_same_root_metadata_falls_back_to_last_unambiguous_checkpoint() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "11".repeat(32),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "22".repeat(32),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: e1.state_root_hex.clone(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: "33".repeat(32),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2]).unwrap();
    assert_eq!(
        got.map(|cp| cp.height),
        Some(1),
        "same-height checkpoint tuples that disagree on wal_entry_hash_hex must fail closed back to the last unambiguous checkpoint even when state_root_hex matches"
    );
}

#[test]
fn wal_checkpoint_accepts_identical_duplicate_checkpoint_evidence() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    let checkpoints = vec![checkpoint.clone(), checkpoint.clone()];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[wal_entry]).unwrap();

    assert_eq!(
        got,
        Some(checkpoint),
        "checkpoint recovery should accept byte-identical duplicate checkpoint tuples so duplicated canonical audit evidence does not fail closed merely because it was recorded twice"
    );
}

#[test]
fn node_recovery_conflicting_same_height_same_root_metadata_falls_back_to_last_unambiguous_checkpoint() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "11".repeat(32),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "22".repeat(32),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: e1.state_root_hex.clone(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: "33".repeat(32),
        },
    ];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[e1, e2]).unwrap();
    assert_eq!(
        got.map(|cp| cp.height),
        Some(1),
        "node recovery must fail closed back to the last unambiguous checkpoint when same-height checkpoint tuples disagree on wal_entry_hash_hex even if state_root_hex matches"
    );
}

#[test]
fn node_recovery_rejects_same_height_checkpoint_state_root_ambiguity_even_when_wal_hash_matches() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "11".repeat(32),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "22".repeat(32),
        prev_hash_hex: Some(h1.clone()),
    };
    let e2_hash = e2.content_hash_hex();

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: e1.state_root_hex.clone(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: e2.state_root_hex.clone(),
            wal_entry_hash_hex: e2_hash.clone(),
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "33".repeat(32),
            wal_entry_hash_hex: e2_hash,
        },
    ];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[e1, e2]).unwrap();
    assert_eq!(
        got.map(|cp| cp.height),
        Some(1),
        "node recovery must fail closed back to the last unambiguous checkpoint when same-height checkpoint tuples reuse one canonical WAL hash but disagree on state_root_hex"
    );
}

#[test]
fn node_recovery_accepts_identical_duplicate_checkpoint_evidence() {
    let wal_entry = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "proposal-1".into(),
        committed: true,
        state_root_hex: "ab".repeat(32),
        prev_hash_hex: None,
    };
    let checkpoint = CheckpointMeta {
        height: wal_entry.height,
        state_root_hex: wal_entry.state_root_hex.clone(),
        wal_entry_hash_hex: wal_entry.content_hash_hex(),
    };
    let checkpoints = vec![checkpoint.clone(), checkpoint.clone()];

    let got = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &[wal_entry]).unwrap();

    assert_eq!(
        got,
        Some(checkpoint),
        "node recovery should accept byte-identical duplicate checkpoint tuples so duplicated canonical audit evidence does not fail closed merely because it was recorded twice"
    );
}
