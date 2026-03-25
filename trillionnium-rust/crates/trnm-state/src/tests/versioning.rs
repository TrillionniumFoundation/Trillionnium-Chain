use super::*;

#[test]
fn put_and_version_update() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 7,
        creator: "alice".into(),
        bounty: 10,
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
    let r1 = st.put_task_new(t.clone()).unwrap();
    assert_eq!(r1.version, 1);

    let mut t2 = t;
    t2.status = TaskStatus::Assigned;
    let r2 = st.update_task(r1, t2).unwrap();
    assert_eq!(r2.version, 2);
}

#[test]
fn version_conflict() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 1,
        creator: "alice".into(),
        bounty: 1,
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
    let r1 = st.put_task_new(t.clone()).unwrap();
    let _ = st.update_task(r1.clone(), t.clone()).unwrap();
    let err = st.update_task(r1, t).unwrap_err();
    assert!(err.contains("version conflict"));
}

#[test]
fn update_task_rejects_embedded_task_id_mismatch() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 11,
        creator: "alice".into(),
        bounty: 1,
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
    let task_ref = st.put_task_new(t.clone()).unwrap();
    let original = st.get_task(task_ref.id).unwrap();

    let mut mismatched = original.clone();
    mismatched.task_id += 1;
    mismatched.status = TaskStatus::Assigned;

    let err = st.update_task(task_ref, mismatched).unwrap_err();
    assert!(err.contains("task id mismatch"));
    assert_eq!(st.get_task(original.task_id).unwrap(), original);
    assert!(st.get_task(original.task_id + 1).is_none());
}

#[test]
fn update_proposal_rejects_embedded_proposal_id_mismatch() {
    let mut st = StateStore::new();
    let proposal = GovProposalObject {
        proposal_id: 21,
        proposer: "alice".into(),
        title: "p".into(),
        description: "d".into(),
        status: GovProposalStatus::Draft,
        yes_votes: 0,
        no_votes: 0,
        created_at_height: 1,
        version: 1,
    };
    let proposal_ref = st.put_proposal_new(proposal.clone()).unwrap();
    let original = st.get_proposal(proposal_ref.id).unwrap();

    let mut mismatched = original.clone();
    mismatched.proposal_id += 1;
    mismatched.status = GovProposalStatus::Voting;

    let err = st.update_proposal(proposal_ref, mismatched).unwrap_err();
    assert!(err.contains("proposal id mismatch"));
    assert_eq!(st.get_proposal(original.proposal_id).unwrap(), original);
    assert!(st.get_proposal(original.proposal_id + 1).is_none());
}

#[test]
fn put_task_new_rejects_zero_id() {
    let mut st = StateStore::new();
    let err = st
        .put_task_new(TaskObject {
            task_id: 0,
            creator: "alice".into(),
            bounty: 10,
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
        })
        .unwrap_err();

    assert!(err.contains("non-zero"));
    assert!(st.get_task(0).is_none());
}

#[test]
fn put_proposal_new_rejects_zero_id() {
    let mut st = StateStore::new();
    let err = st
        .put_proposal_new(GovProposalObject {
            proposal_id: 0,
            proposer: "alice".into(),
            title: "p".into(),
            description: "d".into(),
            status: GovProposalStatus::Draft,
            yes_votes: 0,
            no_votes: 0,
            created_at_height: 1,
            version: 1,
        })
        .unwrap_err();

    assert!(err.contains("non-zero"));
    assert!(st.get_proposal(0).is_none());
}
