use super::*;

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
fn task_challenge_deadline_height_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let mut st2 = StateStore::new();

    let base_task = TaskObject {
        task_id: 8_001,
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
    changed_task.challenge_deadline_height = Some(31);

    st1.put_task_new(base_task).unwrap();
    st2.put_task_new(changed_task).unwrap();

    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate task challenge_deadline_height so retained proof-expiry semantics cannot hash identically"
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
