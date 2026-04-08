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
fn update_task_rejects_cross_type_object_ref_fail_closed() {
    let mut st = StateStore::new();
    let proposal_ref = st
        .put_proposal_new(GovProposalObject {
            proposal_id: 61,
            proposer: "alice".into(),
            title: "p".into(),
            description: "d".into(),
            status: GovProposalStatus::Draft,
            yes_votes: 0,
            no_votes: 0,
            created_at_height: 1,
            version: 1,
        })
        .unwrap();
    let original_proposal = st.get_proposal(proposal_ref.id).unwrap();

    let err = st
        .update_task(
            proposal_ref,
            TaskObject {
                task_id: original_proposal.proposal_id,
                creator: "alice".into(),
                bounty: 10,
                status: TaskStatus::Assigned,
                proof_type: Default::default(),
                metadata: None,
                worker: Some("worker-1".into()),
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
                version: proposal_ref.version,
            },
        )
        .unwrap_err();

    assert!(err.contains("object type mismatch"));
    assert_eq!(st.get_proposal(original_proposal.proposal_id).unwrap(), original_proposal);
    assert!(st.get_task(original_proposal.proposal_id).is_none());
}

#[test]
fn update_proposal_rejects_cross_type_object_ref_fail_closed() {
    let mut st = StateStore::new();
    let task_ref = st
        .put_task_new(TaskObject {
            task_id: 71,
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
        .unwrap();
    let original_task = st.get_task(task_ref.id).unwrap();

    let err = st
        .update_proposal(
            task_ref,
            GovProposalObject {
                proposal_id: original_task.task_id,
                proposer: "alice".into(),
                title: "p".into(),
                description: "d".into(),
                status: GovProposalStatus::Voting,
                yes_votes: 1,
                no_votes: 0,
                created_at_height: 1,
                version: task_ref.version,
            },
        )
        .unwrap_err();

    assert!(err.contains("object type mismatch"));
    assert_eq!(st.get_task(original_task.task_id).unwrap(), original_task);
    assert!(st.get_proposal(original_task.task_id).is_none());
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

#[test]
fn update_task_rejects_payload_version_mismatch() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 31,
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
    let task_ref = st.put_task_new(t.clone()).unwrap();
    let original = st.get_task(task_ref.id).unwrap();

    let mut mismatched = original.clone();
    mismatched.status = TaskStatus::Assigned;
    mismatched.version += 1;

    let err = st.update_task(task_ref, mismatched).unwrap_err();
    assert!(err.contains("payload version mismatch"));
    assert_eq!(st.get_task(original.task_id).unwrap(), original);
}

#[test]
fn update_proposal_rejects_payload_version_mismatch() {
    let mut st = StateStore::new();
    let proposal = GovProposalObject {
        proposal_id: 41,
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
    mismatched.status = GovProposalStatus::Voting;
    mismatched.version += 1;

    let err = st.update_proposal(proposal_ref, mismatched).unwrap_err();
    assert!(err.contains("payload version mismatch"));
    assert_eq!(st.get_proposal(original.proposal_id).unwrap(), original);
}

#[test]
fn restore_task_rejects_zero_id_fail_closed() {
    let mut st = StateStore::new();

    st.restore_task(
        0,
        Some(TaskObject {
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
        }),
    );

    assert!(
        st.get_task(0).is_none(),
        "restore_task must fail closed when replay/restore input targets canonical object id 0"
    );
    assert!(st.get_ref(0).is_none());
}

#[test]
fn restore_task_rejects_zero_version_fail_closed() {
    let mut st = StateStore::new();

    st.restore_task(
        17,
        Some(TaskObject {
            task_id: 17,
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
            version: 0,
        }),
    );

    assert!(
        st.get_task(17).is_none(),
        "restore_task must fail closed when replay/restore input carries version 0"
    );
    assert!(st.get_ref(17).is_none());
}

#[test]
fn restore_task_rejects_cross_type_id_takeover_fail_closed() {
    let mut st = StateStore::new();
    st.restore_gov_param(
        29,
        Some(GovParamObject {
            key_id: 29,
            key: "monetary_base_burn_per_tick".into(),
            value: "11".into(),
            version: 1,
        }),
    );
    let root_before = st.state_root();

    st.restore_task(
        29,
        Some(TaskObject {
            task_id: 29,
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
        }),
    );

    assert!(st.get_task(29).is_none());
    assert_eq!(
        st.get_param(29)
            .map(|param| (param.key_id, param.key, param.value, param.version)),
        Some((29, "monetary_base_burn_per_tick".into(), "11".into(), 1)),
        "restore_task must not evict an existing non-task object on a cross-type restore attempt"
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "cross-type restore attempts must leave canonical state unchanged"
    );
}

#[test]
fn restore_task_cross_type_attempt_scrubs_stale_pending_resolve_on_same_id() {
    let mut st = StateStore::new();
    st.restore_pending_resolve_approval(
        29,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );
    st.restore_gov_param(
        29,
        Some(GovParamObject {
            key_id: 29,
            key: "monetary_base_burn_per_tick".into(),
            value: "11".into(),
            version: 1,
        }),
    );
    let root_before = st.state_root();

    st.restore_task(
        29,
        Some(TaskObject {
            task_id: 29,
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
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(29),
        None,
        "cross-type task restore attempts must scrub stale staged resolve state bound to a non-task slot"
    );
    assert_eq!(
        st.get_param(29)
            .map(|param| (param.key_id, param.key, param.value, param.version)),
        Some((29, "monetary_base_burn_per_tick".into(), "11".into(), 1)),
        "cross-type task restore attempts must preserve the canonical non-task occupant"
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "scrubbing stale task-only residue on a cross-type restore attempt must preserve the canonical root"
    );
}

#[test]
fn restore_task_rejects_cross_type_gov_proposal_id_takeover_fail_closed() {
    let mut st = StateStore::new();
    let proposal_ref = st
        .put_proposal_new(GovProposalObject {
            proposal_id: 39,
            proposer: "alice".into(),
            title: "p".into(),
            description: "d".into(),
            status: GovProposalStatus::Draft,
            yes_votes: 0,
            no_votes: 0,
            created_at_height: 1,
            version: 1,
        })
        .unwrap();
    let original_proposal = st.get_proposal(proposal_ref.id).unwrap();
    let root_before = st.state_root();

    st.restore_task(
        proposal_ref.id,
        Some(TaskObject {
            task_id: proposal_ref.id,
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
        }),
    );

    assert!(st.get_task(proposal_ref.id).is_none());
    assert_eq!(
        st.get_proposal(proposal_ref.id).unwrap(),
        original_proposal,
        "restore_task must not evict an existing governance proposal on a cross-type restore attempt"
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "cross-type restore attempts against proposal slots must leave the canonical state root unchanged"
    );
}

#[test]
fn restore_pending_resolve_approval_requires_existing_challenged_task() {
    let mut st = StateStore::new();
    let root_before = st.state_root();

    st.restore_pending_resolve_approval(
        29,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(29),
        None,
        "restore_pending_resolve_approval must fail closed when the challenged task is absent"
    );
    assert_eq!(
        st.state_root(),
        root_before,
        "orphan pending resolve approvals must not perturb canonical state"
    );
}

#[test]
fn restore_gov_param_scrubs_stale_pending_resolve_on_same_id() {
    let mut st = StateStore::new();
    st.restore_pending_resolve_approval(
        29,
        Some(PendingResolveApprovalSnapshot {
            slash_worker: true,
            confirmations: 1,
            first_approver: "authority-a".into(),
            authority_set: "authority-a,authority-b".into(),
            task_version: 1,
        }),
    );
    assert_eq!(st.pending_resolve_approval(29), Some((true, 1)));

    st.restore_gov_param(
        29,
        Some(GovParamObject {
            key_id: 29,
            key: "monetary_base_burn_per_tick".into(),
            value: "11".into(),
            version: 1,
        }),
    );

    assert_eq!(
        st.pending_resolve_approval(29),
        None,
        "restoring a non-task object into an id slot must scrub stale staged resolve state bound to the old task identity"
    );
    assert_eq!(
        st.get_param(29)
            .map(|param| (param.key_id, param.key, param.value, param.version)),
        Some((29, "monetary_base_burn_per_tick".into(), "11".into(), 1)),
        "restore_gov_param should still materialize the canonical governance object after scrubbing stale task-only residue"
    );
}
