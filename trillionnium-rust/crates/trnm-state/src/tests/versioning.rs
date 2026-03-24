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
