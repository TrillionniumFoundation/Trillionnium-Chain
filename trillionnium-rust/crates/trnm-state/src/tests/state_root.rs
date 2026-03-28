use super::*;

#[test]
fn state_root_changes_when_task_security_fields_change() {
    let mut st = StateStore::new();
    let task = TaskObject {
        task_id: 42,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };

    st.put_task_new(task.clone()).unwrap();
    let root_before = st.state_root();

    let mut changed = task;
    changed.challenge_bond_forfeited = Some(true);
    let current_ref = st.get_ref(42).unwrap();
    st.update_task(current_ref, changed).unwrap();
    let root_after = st.state_root();

    assert_ne!(root_before, root_after);
}

#[test]
fn state_root_changes_when_terminal_challenge_retention_metadata_changes() {
    let mut st_a = StateStore::new();
    let terminal_task = TaskObject {
        task_id: 420,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    st_a.put_task_new(terminal_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = terminal_task;
    changed.resolve_deadline_height = Some(36);
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "terminal challenged-task retention metadata must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_terminal_challenge_forfeit_outcome_changes() {
    let mut st_a = StateStore::new();
    let terminal_task = TaskObject {
        task_id: 422,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    st_a.put_task_new(terminal_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = terminal_task;
    changed.challenge_bond_forfeited = Some(true);
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "terminal challenged-task collateral forfeit outcome must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_terminal_challenge_challenger_changes() {
    let mut st_a = StateStore::new();
    let terminal_task = TaskObject {
        task_id: 423,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    st_a.put_task_new(terminal_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = terminal_task;
    changed.challenger = Some("carol".into());
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "terminal challenged-task challenger identity must contribute to state root so retained collateral/proof audit trails cannot hash identically"
    );
}

#[test]
fn state_root_changes_when_terminal_challenge_bond_amount_changes() {
    let mut st_a = StateStore::new();
    let terminal_task = TaskObject {
        task_id: 424,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    st_a.put_task_new(terminal_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = terminal_task;
    changed.challenge_bond = Some(501);
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "terminal challenged-task retained challenge bond amount must contribute to state root so collateral accounting snapshots cannot hash identically"
    );
}

#[test]
fn state_root_changes_when_unchallenged_terminal_retention_snapshot_changes() {
    let mut st_a = StateStore::new();
    let completed_task = TaskObject {
        task_id: 421,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };
    st_a.put_task_new(completed_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = completed_task;
    changed.challenge_window_blocks_snapshot = Some(41);
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "unchallenged terminal retention snapshot must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_slashed_terminal_retention_metadata_changes() {
    let mut st_a = StateStore::new();
    let slashed_task = TaskObject {
        task_id: 425,
        creator: "alice".into(),
        bounty: 100,
        status: TaskStatus::Slashed,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker-1".into()),
        committed_hash: Some([1u8; 32]),
        result_hash: Some([2u8; 32]),
        reveal_salt: Some([3u8; 32]),
        committed_at_height: Some(10),
        reveal_deadline_height: Some(20),
        challenge_deadline_height: Some(30),
        challenge_window_blocks_snapshot: Some(40),
        challenged_at_height: Some(25),
        resolve_deadline_height: Some(35),
        challenge_bond: Some(500),
        challenger: Some("bob".into()),
        challenge_bond_forfeited: Some(false),
        version: 1,
    };
    st_a.put_task_new(slashed_task.clone()).unwrap();

    let mut st_b = StateStore::new();
    let mut changed = slashed_task;
    changed.resolve_deadline_height = Some(36);
    st_b.put_task_new(changed).unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "slashed terminal challenge-retention metadata must contribute to state root so later collateral/proof audits cannot hash distinct slash-settlement trails identically"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_first_approver_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(500, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(500, 1, true, "authority-b", "authority-a,authority-b")
        .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve first approver must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_confirmation_count_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(
        501,
        1,
        true,
        "authority-a",
        "authority-a,authority-b,authority-c",
    )
    .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(
        501,
        1,
        true,
        "authority-a",
        "authority-a,authority-b,authority-c",
    )
    .unwrap();
    st_b.stage_or_confirm_resolve_approval(
        501,
        1,
        true,
        "authority-b",
        "authority-a,authority-b,authority-c",
    )
    .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve confirmation count must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_task_version_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(501, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(501, 2, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve task version snapshot must contribute to state root"
    );
}

#[test]
fn state_root_changes_when_pending_resolve_authority_set_changes() {
    let mut st_a = StateStore::new();
    st_a.stage_or_confirm_resolve_approval(501, 1, true, "authority-a", "authority-a,authority-b")
        .unwrap();

    let mut st_b = StateStore::new();
    st_b.stage_or_confirm_resolve_approval(
        501,
        1,
        true,
        "authority-a",
        "authority-a,authority-b,authority-c",
    )
    .unwrap();

    assert_ne!(
        st_a.state_root(),
        st_b.state_root(),
        "pending resolve authority set must contribute to state root"
    );
}
