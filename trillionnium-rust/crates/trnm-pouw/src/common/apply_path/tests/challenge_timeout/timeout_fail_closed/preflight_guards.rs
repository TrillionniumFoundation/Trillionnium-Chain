use super::*;

#[test]
fn timeout_preflight_rejects_conflicting_challenge_transfer_modes() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 77,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, true, true).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("mode conflict")));
}

#[test]
fn timeout_preflight_rejects_refund_without_challenger() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 78,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: None,
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, false, true).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
}

#[test]
fn timeout_preflight_rejects_forfeit_without_challenger() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 78,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: None,
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, true, false).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
}

#[test]
fn timeout_preflight_rejects_transfer_when_bond_not_posted() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 79,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: None,
        challenge_bond_forfeited: None,
        challenger: Some("challenger".into()),
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, true, false).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("without posted challenge bond")));
}

#[test]
fn timeout_preflight_rejects_refund_with_blank_challenger_identity() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 80,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: Some(false),
        challenger: Some("   ".into()),
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, false, true).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("blank challenger identity")));
}

#[test]
fn timeout_preflight_rejects_refund_with_hidden_char_challenger_identity() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 81,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: Some(false),
        challenger: Some("challenger\u{200b}".into()),
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, false, true).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity")));
}

#[test]
fn timeout_preflight_rejects_forfeit_with_noncanonical_challenger_identity() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 82,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: Some(true),
        challenger: Some("challenger\u{200b}".into()),
        version: 0,
    };

    let err = preflight_timeout_transfers(&st, &task, true, false).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity")));
}
