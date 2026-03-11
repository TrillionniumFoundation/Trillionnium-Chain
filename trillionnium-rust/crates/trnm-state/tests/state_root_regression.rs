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
fn pending_gov_updates_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    // Base states are identical
    assert_eq!(st1.state_root(), st2.state_root());

    // Add a pending update to st1 only
    st1.set_gov_param(1000, 7001, "max_block_ms".to_string(), "5000".to_string())
        .unwrap();

    // Roots should now differ because of pending_gov_updates
    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate pending governance updates"
    );
}
