use super::*;

#[test]
fn commit_requires_assigned() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 11, "alice".into(), 10).unwrap();
    let err = apply_commit_result(&mut st, r1, "worker1".into(), [1u8; 32]).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));
}
#[test]
fn create_task_rejects_noncanonical_creator_identity() {
    let mut st = seeded_state();

    let blank = apply_create_task(&mut st, 209, "   ".into(), 10).unwrap_err();
    assert!(matches!(blank, PouwError::Unauthorized));

    let padded = apply_create_task(&mut st, 210, " alice ".into(), 10).unwrap_err();
    assert!(matches!(padded, PouwError::Unauthorized));
}
#[test]
fn create_task_rejects_dirty_creator_actor_ids() {
    for (i, dirty_creator) in dirty_actor_ids().into_iter().enumerate() {
        let mut st = seeded_state();
        let err =
            apply_create_task(&mut st, 21_050 + i as u64, dirty_creator.into(), 10).unwrap_err();
        assert!(
            matches!(err, PouwError::Unauthorized),
            "create_task should reject dirty creator actor id: {:?}",
            dirty_creator
        );
    }
}
#[test]
fn accept_task_rejects_noncanonical_worker_identity() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 211, "alice".into(), 10).unwrap();

    let blank = apply_accept_task(&mut st, r1.clone(), "   ".into()).unwrap_err();
    assert!(matches!(blank, PouwError::Unauthorized));

    let padded = apply_accept_task(&mut st, r1, " worker1 ".into()).unwrap_err();
    assert!(matches!(padded, PouwError::Unauthorized));
}
#[test]
fn accept_task_rejects_dirty_worker_actor_ids() {
    for (i, dirty_worker) in dirty_actor_ids().into_iter().enumerate() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 21_100 + i as u64, "alice".into(), 10).unwrap();
        let err = apply_accept_task(&mut st, r1, dirty_worker.into()).unwrap_err();
        assert!(
            matches!(err, PouwError::Unauthorized),
            "accept should reject dirty worker actor id: {:?}",
            dirty_worker
        );
    }
}
#[test]
fn commit_worker_must_match_assigned_worker() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 12, "alice".into(), 10).unwrap();
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let err = apply_commit_result(&mut st, r2, "worker2".into(), [1u8; 32]).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));
}
