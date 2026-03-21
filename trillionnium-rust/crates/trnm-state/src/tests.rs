use super::governance::{is_sensitive_gov_param, GOV_ALLOWED_KEYS, GOV_SENSITIVE_KEYS};
use super::*;
use trnm_types::{GovProposalObject, GovProposalStatus, TaskObject, TaskStatus};

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
fn resolve_approval_requires_two_distinct_approvers_before_ready() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first, "single approver must not finalize resolve approval");
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-a", "authority-a,authority-b")
        .expect_err("same approver must not satisfy multi-party confirmation");
    assert!(dup_err.contains("distinct approver"));
    assert_eq!(st.pending_resolve_approval(42), Some((true, 1)));

    let second = st
        .stage_or_confirm_resolve_approval(42, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(
        second,
        "second distinct approver must finalize resolve approval"
    );
    assert_eq!(st.pending_resolve_approval(42), Some((true, 2)));

    st.clear_pending_resolve_approval(42);
    assert!(st.pending_resolve_approval(42).is_none());
}

#[test]
fn resolve_approval_rejects_decision_mismatch_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(7, 1, false, "authority-a", "authority-a,authority-b")
        .expect("initial non-slash approval should stage");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(7), Some((false, 1)));

    let mismatch = st
        .stage_or_confirm_resolve_approval(7, 1, true, "authority-b", "authority-a,authority-b")
        .expect_err("mismatched slash decision must fail closed");
    assert!(mismatch.contains("decision mismatch"));
    assert_eq!(
        st.pending_resolve_approval(7),
        Some((false, 1)),
        "decision mismatch must not mutate staged confirmation"
    );
}

#[test]
fn resolve_approval_rejects_post_quorum_replay_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);

    let second = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-b", "authority-a,authority-b")
        .expect("second distinct approver should finalize");
    assert!(second);
    assert_eq!(st.pending_resolve_approval(88), Some((true, 2)));

    let replay_err = st
        .stage_or_confirm_resolve_approval(88, 1, true, "authority-c", "authority-a,authority-b")
        .expect_err("post-quorum replay must be rejected");
    assert!(
        replay_err.contains("already finalized")
            || replay_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(88),
        Some((true, 2)),
        "post-quorum replay must not mutate confirmation state"
    );
}

#[test]
fn resolve_approval_rejects_case_drift_duplicate_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(77, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(77), Some((true, 1)));

    let dup_err = st
        .stage_or_confirm_resolve_approval(77, 1, true, "Authority-A", "authority-a,authority-b")
        .expect_err("case-drift duplicate approver must be rejected");
    assert!(
        dup_err.contains("distinct approver") || dup_err.contains("configured authority member")
    );
    assert_eq!(
        st.pending_resolve_approval(77),
        Some((true, 1)),
        "case-drift duplicate must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_whitespace_drift_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(78, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(78), Some((true, 1)));

    let whitespace_err = st
        .stage_or_confirm_resolve_approval(78, 1, true, " authority-a ", "authority-a,authority-b")
        .expect_err("whitespace-drift approver must be rejected");
    assert!(whitespace_err.contains("must not contain whitespace"));
    assert_eq!(
        st.pending_resolve_approval(78),
        Some((true, 1)),
        "whitespace-drift approver must not increase confirmation count"
    );
}

#[test]
fn resolve_approval_rejects_multiactor_delimited_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(79, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(79), Some((true, 1)));

    for bad_actor in ["authority-a,authority-b", "authority-a;authority-b"] {
        let err = st
            .stage_or_confirm_resolve_approval(79, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("delimited approver id must be rejected");
        assert!(err.contains("single canonical actor id"));
        assert_eq!(
            st.pending_resolve_approval(79),
            Some((true, 1)),
            "invalid approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn resolve_approval_rejects_system_or_treasury_approver_without_mutation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(80, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(80), Some((true, 1)));

    for bad_actor in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "System",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Forfeits",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(80, 1, true, bad_actor, "authority-a,authority-b")
            .expect_err("system/treasury approver must be rejected");
        assert!(err.contains("explicit non-system authority"));
        assert_eq!(
            st.pending_resolve_approval(80),
            Some((true, 1)),
            "reserved approver id must not mutate staged confirmations"
        );
    }
}

#[test]
fn resolve_approval_rejects_noncanonical_authority_set_without_mutation() {
    let mut st = StateStore::new();

    for malformed_set in [
        "authority-a",
        "authority-a,",
        "authority-a, authority-b",
        "authority-a;authority-b",
        "authority-a,AUTHORITY-A",
        "authority-a,system",
    ] {
        let err = st
            .stage_or_confirm_resolve_approval(8_882, 1, true, "authority-a", malformed_set)
            .expect_err("non-canonical authority set must fail closed");
        assert!(
            err.contains("authority set"),
            "unexpected error for malformed set {malformed_set}: {err}"
        );
        assert_eq!(
            st.pending_resolve_approval(8_882),
            None,
            "malformed authority set must not stage pending approvals"
        );
    }
}

#[test]
fn resolve_approval_clears_stale_stage_on_task_version_change() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(82, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(82), Some((true, 1)));

    let version_err = st
        .stage_or_confirm_resolve_approval(82, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task version change must fail closed and clear stale stage");
    assert!(version_err.contains("task version changed"));
    assert_eq!(st.pending_resolve_approval(82), None);
    assert_eq!(st.pending_resolve_first_approver(82), None);
}

#[test]
fn resolve_approval_task_version_mismatch_invalidates_cached_state_root() {
    let mut st = StateStore::new();

    st.stage_or_confirm_resolve_approval(8_283, 3, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");

    let root_with_pending = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(8_283, 4, true, "authority-b", "authority-a,authority-b")
        .expect_err("task-version mismatch should clear staged approval");
    assert!(err.contains("task version changed"));

    let root_after_clear = st.state_root();

    let baseline = StateStore::new().state_root();
    assert_eq!(st.pending_resolve_approval(8_283), None);
    assert_ne!(
        root_with_pending, root_after_clear,
        "clearing stale pending resolve approval must invalidate cached state root"
    );
    assert_eq!(
        root_after_clear, baseline,
        "after stale-stage clear, state root should match an empty store"
    );
}

#[test]
fn resolve_approval_clears_stale_stage_on_authority_set_rotation() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(81), Some((true, 1)));

    let rotated_err = st
        .stage_or_confirm_resolve_approval(81, 7, true, "authority-c", "authority-a,authority-c")
        .expect_err("authority set rotation must fail closed and clear stale stage");
    assert!(rotated_err.contains("authority set changed"));
    assert_eq!(st.pending_resolve_approval(81), None);
    assert_eq!(st.pending_resolve_first_approver(81), None);
}

#[test]
fn resolve_approval_clears_stale_stage_on_authority_set_case_drift() {
    let mut st = StateStore::new();

    let first = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed");
    assert!(!first);
    assert_eq!(st.pending_resolve_approval(8_181), Some((true, 1)));

    let case_drift_err = st
        .stage_or_confirm_resolve_approval(8_181, 7, true, "Authority-B", "authority-a,Authority-B")
        .expect_err("authority set case drift must fail closed and clear stale stage");
    assert!(case_drift_err.contains("authority set changed"));
    assert_eq!(st.pending_resolve_approval(8_181), None);
    assert_eq!(st.pending_resolve_first_approver(8_181), None);
}

#[test]
fn governance_minimal_state_machine() {
    let mut st = StateStore::new();
    let p = GovProposalObject {
        proposal_id: 9001,
        title: "update param x".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let r1 = st.put_proposal_new(p).unwrap();

    let r2 = st
        .transition_proposal_status(r1, GovProposalStatus::Voting)
        .unwrap();
    let r3 = st
        .transition_proposal_status(r2, GovProposalStatus::Passed)
        .unwrap();
    let _r4 = st
        .transition_proposal_status(r3, GovProposalStatus::Executed)
        .unwrap();

    let cur = st.get_proposal(9001).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Executed);
}

#[test]
fn governance_invalid_transition_rejected() {
    let mut st = StateStore::new();
    let p = GovProposalObject {
        proposal_id: 9002,
        title: "bad jump".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let r1 = st.put_proposal_new(p).unwrap();
    let err = st
        .transition_proposal_status(r1, GovProposalStatus::Passed)
        .unwrap_err();
    assert!(err.contains("invalid governance transition"));
}

#[test]
fn governance_pause_does_not_bypass_invalid_transition_guards() {
    // Merge-gate guard: emergency pause must not weaken proposal transition checks.
    let mut st = StateStore::new();

    // Enter paused mode through the checked governance path.
    let paused = st
        .set_gov_param(9_200, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(paused, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());

    let proposal = GovProposalObject {
        proposal_id: 9_201,
        title: "paused invalid jump".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let expected = st.put_proposal_new(proposal).unwrap();

    let err = st
        .transition_proposal_status(expected, GovProposalStatus::Passed)
        .unwrap_err();
    assert!(err.contains("invalid governance transition"));

    // Proposal must remain unchanged after failed transition while paused.
    let cur = st.get_proposal(9_201).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Draft);
    assert_eq!(
        cur.version, 1,
        "failed transition while paused must not mutate proposal version"
    );
}

#[test]
fn governance_pause_does_not_block_valid_transition_path() {
    // Merge-gate guard: emergency pause is an execution-risk brake, not a governance
    // proposal lifecycle freeze. Valid state-machine transitions must still work.
    let mut st = StateStore::new();
    st.set_gov_param(9_210, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let proposal = GovProposalObject {
        proposal_id: 9_211,
        title: "paused valid path".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    let mut expected = st.put_proposal_new(proposal).unwrap();

    expected = st
        .transition_proposal_status(expected, GovProposalStatus::Voting)
        .expect("Draft->Voting must remain valid while paused");
    expected = st
        .transition_proposal_status(expected, GovProposalStatus::Passed)
        .expect("Voting->Passed must remain valid while paused");
    let _ = st
        .transition_proposal_status(expected, GovProposalStatus::Executed)
        .expect("Passed->Executed must remain valid while paused");

    let cur = st.get_proposal(9_211).unwrap();
    assert_eq!(cur.status, GovProposalStatus::Executed);
}

#[test]
fn governance_terminal_states_are_non_transitional() {
    let mut st = StateStore::new();

    let executed = GovProposalObject {
        proposal_id: 9003,
        title: "already executed".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Executed,
        version: 1,
    };
    let executed_ref = st.put_proposal_new(executed).unwrap();
    let err_executed = st
        .transition_proposal_status(executed_ref, GovProposalStatus::Voting)
        .unwrap_err();
    assert!(err_executed.contains("invalid governance transition"));

    let rejected = GovProposalObject {
        proposal_id: 9004,
        title: "already rejected".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Rejected,
        version: 1,
    };
    let rejected_ref = st.put_proposal_new(rejected).unwrap();
    let err_rejected = st
        .transition_proposal_status(rejected_ref, GovProposalStatus::Voting)
        .unwrap_err();
    assert!(err_rejected.contains("invalid governance transition"));
}

#[test]
fn governance_transition_matrix_remains_strict_and_exhaustive() {
    fn expected_transition_allowed(from: GovProposalStatus, to: GovProposalStatus) -> bool {
        // Exhaustive merge-gate guard: adding/changing statuses requires updating this matrix.
        match (from, to) {
            (GovProposalStatus::Draft, GovProposalStatus::Voting)
            | (GovProposalStatus::Voting, GovProposalStatus::Passed)
            | (GovProposalStatus::Voting, GovProposalStatus::Rejected)
            | (GovProposalStatus::Passed, GovProposalStatus::Executed) => true,
            (GovProposalStatus::Draft, _)
            | (GovProposalStatus::Voting, _)
            | (GovProposalStatus::Passed, _)
            | (GovProposalStatus::Rejected, _)
            | (GovProposalStatus::Executed, _) => false,
        }
    }

    let statuses = [
        GovProposalStatus::Draft,
        GovProposalStatus::Voting,
        GovProposalStatus::Passed,
        GovProposalStatus::Rejected,
        GovProposalStatus::Executed,
    ];

    for &from in &statuses {
        for &to in &statuses {
            let mut st = StateStore::new();
            let proposal_id = 95_000 + (from as u64) * 10 + (to as u64);
            let proposal = GovProposalObject {
                proposal_id,
                title: "matrix".into(),
                proposer: "merge-gate".into(),
                status: from,
                version: 1,
            };
            let expected = st.put_proposal_new(proposal).unwrap();
            let outcome = st.transition_proposal_status(expected, to);

            if expected_transition_allowed(from, to) {
                assert!(
                    outcome.is_ok(),
                    "expected transition to succeed for {:?}->{:?}",
                    from,
                    to
                );
            } else {
                let err = outcome.unwrap_err();
                assert!(
                    err.contains("invalid governance transition"),
                    "expected invalid transition for {:?}->{:?}, got: {}",
                    from,
                    to,
                    err
                );
            }
        }
    }
}

#[test]
fn governance_param_whitelist_enforced() {
    let mut st = StateStore::new();
    let ok = st
        .set_gov_param_unchecked(7001, "max_block_ms".into(), "10".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let cur = st.get_param(7001).unwrap();
    assert_eq!(cur.key, "max_block_ms");
    assert_eq!(cur.value, "10");

    let bounty_ok = st
        .set_gov_param_unchecked(7003, "challenge_success_bounty".into(), "5".into())
        .unwrap();
    assert_eq!(bounty_ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7002, "forbidden_key".into(), "1".into())
        .unwrap_err();
    assert!(err.contains("not allowed"));
}

#[test]
fn governance_param_schema_rejects_invalid_u64_values() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(7101, "max_block_ms".into(), "abc".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(7101, "max_parallel_workers".into(), "32".into())
        .unwrap();
    assert_eq!(ok.version, 1);

    let err = st
        .set_gov_param_unchecked(7102, "challenge_window_blocks".into(), "99".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7103, "min_worker_stake".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7104, "challenge_min_bond".into(), "0".into())
        .unwrap_err();
    assert!(err.contains("out of range"));

    let err = st
        .set_gov_param_unchecked(7105, "challenge_success_bounty".into(), "-1".into())
        .unwrap_err();
    assert!(err.contains("expected u64"));

    let err = st
        .set_gov_param_unchecked(
            7105,
            "challenge_min_bond_bounty_bps".into(),
            "100001".into(),
        )
        .unwrap_err();
    assert!(err.contains("out of range"));

    let ok = st
        .set_gov_param_unchecked(
            7106,
            "challenge_min_bond_worker_stake_bps".into(),
            "0".into(),
        )
        .unwrap();
    assert_eq!(ok.version, 1);
}

#[test]
fn governance_key_id_collision_with_non_param_rejected() {
    let mut st = StateStore::new();
    let t = TaskObject {
        task_id: 7400,
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
    st.put_task_new(t).unwrap();

    let err = st
        .set_gov_param_unchecked(7400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err.contains("not GovParam"));

    let p = GovProposalObject {
        proposal_id: 7405,
        title: "change block time".into(),
        proposer: "alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };
    st.put_proposal_new(p).unwrap();

    let err = st
        .set_gov_param_unchecked(7405, "max_block_ms".into(), "20".into())
        .unwrap_err();
    assert!(err.contains("not GovParam"));
}

#[test]
fn governance_non_sensitive_failed_apply_does_not_scrub_pending_queue() {
    // Merge-gate guard: failed writes must be side-effect free for unrelated
    // pending governance state (except explicit Cancel unsupported path).
    let mut st = StateStore::new();

    st.pending_gov_updates.insert(
        "max_block_ms".into(),
        PendingGovParamUpdate {
            key_id: 7_400,
            key: "max_block_ms".into(),
            value: "15".into(),
            activate_at_height: 77_700,
        },
    );

    let task = TaskObject {
        task_id: 7_400,
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
    st.put_task_new(task).unwrap();

    let err_unchecked = st
        .set_gov_param_unchecked(7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_unchecked.contains("not GovParam"));
    assert!(
        st.pending_gov_update("max_block_ms").is_some(),
        "failed unchecked apply must not scrub pending queue"
    );

    let err_checked = st
        .set_gov_param(77_701, 7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_checked.contains("not GovParam"));

    let pending = st
        .pending_gov_update("max_block_ms")
        .expect("failed checked apply must not scrub pending queue");
    assert_eq!(pending.key_id, 7_400);
    assert_eq!(pending.activate_at_height, 77_700);
}

#[test]
fn governance_same_key_different_id_shadow_attempt_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7401, "max_block_ms".into(), "15".into())
        .unwrap();

    let err = st
        .set_gov_param_unchecked(7402, "max_block_ms".into(), "20".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));
}

#[test]
fn governance_readers_use_deterministic_current_value() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "15".into())
        .unwrap();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "20".into())
        .unwrap();

    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_u128("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_string("max_block_ms"), Some("20".into()));
}

#[test]
fn governance_sensitive_update_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7300, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(1_000, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 1_020);

    let err = st
        .set_gov_param(1_019, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));
}

#[test]
fn governance_sensitive_update_accepted_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7301, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let _ = st
        .set_gov_param(2_000, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_020, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();
    match applied {
        GovParamUpdateOutcome::Applied(r) => assert!(r.version >= 2),
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected applied"),
        GovParamUpdateOutcome::Cancelled => panic!("expected applied"),
    }

    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(120));
    assert!(st.pending_gov_update("challenge_min_bond").is_none());
}

#[test]
fn governance_sensitive_noop_update_is_immediate_without_timelock() {
    let mut st = StateStore::new();
    let seeded = st
        .set_gov_param_unchecked(7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_500, 7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    match applied {
        GovParamUpdateOutcome::Applied(r) => {
            assert_eq!(r.id, seeded.id);
            assert_eq!(r.version, seeded.version);
        }
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected immediate no-op apply"),
        GovParamUpdateOutcome::Cancelled => panic!("expected immediate no-op apply"),
    }

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}

#[test]
fn governance_resolve_authority_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7310,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            10_000,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 10_020);

    let err = st
        .set_gov_param(
            10_019,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err.contains("timelock active"));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn governance_resolve_authority_applied_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7311,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let _ = st
        .set_gov_param(
            11_000,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();

    let applied = st
        .set_gov_param(
            11_020,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_non_canonical_value_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            " resolver-v2 ".into(),
        )
        .unwrap_err();
    assert!(err.contains("whitespace") || err.contains("canonical"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_forbidden_separator_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7313,
            "resolve_authority".into(),
            "resolver-a，resolver-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("separator") || err.contains("ASCII ','"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_non_ascii_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7314,
            "resolve_authority".into(),
            "resolver-a,resolvér-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("ASCII-only") || err.contains("whitespace") || err.contains("separator"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_rejects_single_member_update_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7315,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_500,
            7315,
            "resolve_authority".into(),
            "resolver-v3".into(),
        )
        .expect_err("singleton resolve_authority update must be rejected");
    assert!(err.contains("at least two members"), "{err}");

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_resolve_authority_pending_mismatch_behaves_like_sensitive_keys() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 12_020
        }
    ));

    let err_value = st
        .set_gov_param(
            12_005,
            7312,
            "resolve_authority".into(),
            "resolver-v5,resolver-v6".into(),
        )
        .unwrap_err();
    assert!(err_value.contains("pending governance update exists"));

    let err_id = st
        .set_gov_param(
            12_005,
            9999,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err_id.contains("governance key id mismatch for resolve_authority"));

    let pending = st.pending_gov_update("resolve_authority").unwrap();
    assert_eq!(pending.key_id, 7312);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 12_020);
}

#[test]
fn governance_resolve_authority_unchecked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial unchecked resolve_authority write should succeed");

    let err = st
        .set_gov_param_unchecked(
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("unchecked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn governance_resolve_authority_unchecked_path_rejects_reserved_emergency_pause_key_id_alias() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(
            7_999,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect_err("reserved emergency_pause key id must stay pinned on unchecked path");

    assert!(
        err.contains("governance key id mismatch for id 7999: expected_key=emergency_pause, attempted_key=resolve_authority"),
        "{err}"
    );
    assert_eq!(st.gov_param_string("resolve_authority"), None);
    assert!(!st.is_emergency_paused());
}

#[test]
fn governance_resolve_authority_checked_path_rejects_key_id_shadowing_without_state_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let err = st
        .set_gov_param(
            14_000,
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("checked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(
        st.pending_gov_update("resolve_authority").is_none(),
        "rejected key-id shadowing must not enqueue pending updates"
    );
}

#[test]
fn governance_resolve_authority_cancel_wrong_key_id_preserves_pending_update() {
    // Merge-gate guard: cancel for a sensitive resolve_authority timelock must reject
    // key-id drift before any pending queue mutation.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let scheduled = st
        .set_gov_param(
            14_500,
            7314,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority update should schedule");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 14_520
        }
    ));

    let err = st
        .set_gov_param_with_action(
            14_505,
            9001,
            "resolve_authority".into(),
            "ignored-on-cancel".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel with wrong key id must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("wrong-key cancel must not clear pending resolve_authority update");
    assert_eq!(pending.key_id, 7314);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 14_520);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}

#[test]
fn emergency_pause_does_not_mutate_pending_resolve_authority_update() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            13_000,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 13_020
        }
    ));

    st.set_gov_param(13_001, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    st.set_gov_param(13_002, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause toggle must apply immediately");

    assert!(!st.is_emergency_paused());
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should survive pause toggles");
    assert_eq!(pending.key_id, 7313);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 13_020);

    let applied = st
        .set_gov_param(
            13_020,
            7313,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority should still activate at original timelock height");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}

#[test]
fn governance_sensitive_pending_replace_before_activation_resets_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7320, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let first = st
        .set_gov_param(20_000, 7320, "challenge_window_blocks".into(), "110".into())
        .unwrap();
    assert!(matches!(
        first,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_020
        }
    ));

    let replaced = st
        .set_gov_param_with_action(
            20_005,
            7320,
            "challenge_window_blocks".into(),
            "120".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(
        replaced,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_025
        }
    ));

    let pending = st.pending_gov_update("challenge_window_blocks").unwrap();
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 20_025);

    let err = st
        .set_gov_param(20_020, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(20_025, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}

#[test]
fn governance_sensitive_pending_cancel_before_activation_removes_pending() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7321, "challenge_min_bond".into(), "100".into())
        .unwrap();

    st.set_gov_param(21_000, 7321, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let cancelled = st
        .set_gov_param_with_action(
            21_005,
            7321,
            "challenge_min_bond".into(),
            "".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap();
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}

#[test]
fn governance_sensitive_apply_without_pending_is_unchanged() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7322, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(22_000, 7322, "challenge_min_bond".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 22_020
        }
    ));
}

#[test]
fn governance_sensitive_rate_limit_still_enforced_after_replace() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7323, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    st.set_gov_param(23_000, 7323, "challenge_window_blocks".into(), "120".into())
        .unwrap();

    st.set_gov_param_with_action(
        23_005,
        7323,
        "challenge_window_blocks".into(),
        "119".into(),
        GovPendingUpdateAction::Replace,
    )
    .unwrap();

    let err = st
        .set_gov_param_with_action(
            23_006,
            7323,
            "challenge_window_blocks".into(),
            "130".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}

#[test]
fn governance_sensitive_update_excessive_step_change_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7302, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let err = st
        .set_gov_param(3_000, 7302, "challenge_window_blocks".into(), "130".into())
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}

#[test]
fn governance_sensitive_update_bounded_step_change_accepted() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7303, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(4_000, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 4_020
        }
    ));

    let applied = st
        .set_gov_param(4_020, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}

#[test]
fn governance_challenge_success_bounty_is_sensitive_and_timelocked() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7350, "challenge_success_bounty".into(), "1".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(30_000, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 30_020
        }
    ));

    let err = st
        .set_gov_param(30_010, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(30_020, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_success_bounty"), Some(2));
}

#[test]
fn governance_non_sensitive_param_unaffected_by_timelock() {
    let mut st = StateStore::new();
    let r1 = st
        .set_gov_param(5_000, 7304, "max_block_ms".into(), "15".into())
        .unwrap();
    assert!(matches!(r1, GovParamUpdateOutcome::Applied(_)));

    let r2 = st
        .set_gov_param(5_001, 7304, "max_block_ms".into(), "20".into())
        .unwrap();
    assert!(matches!(r2, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert!(st.pending_gov_update("max_block_ms").is_none());
}

#[test]
fn emergency_pause_requires_strict_bool_literal() {
    let mut st = StateStore::new();

    for bad in [
        "TRUE", "False", "1", "yes", " true", "false ", "\ttrue", "\ntrue", "false\n",
    ] {
        let err = st
            .set_gov_param_unchecked(7999, "emergency_pause".into(), bad.into())
            .unwrap_err();
        assert!(err.contains("strict bool"));
    }

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_flag_works() {
    let mut st = StateStore::new();
    assert!(!st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    st.set_gov_param_unchecked(7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_unchecked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: even unchecked writes must keep emergency_pause pinned to 7999.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param_unchecked(8_000, "emergency_pause".into(), "true".into())
        .expect_err("unchecked non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_rejects_non_canonical_key_id() {
    // Merge-gate guard: emergency_pause must remain pinned to canonical key id.
    let mut st = StateStore::new();
    let err = st
        .set_gov_param(8_050, 8_000, "emergency_pause".into(), "true".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation() {
    // Merge-gate guard: key-id mismatch must fail before value schema parsing,
    // so malformed values cannot alter error semantics.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param(8_051, 8_000, "emergency_pause".into(), "TRUE".into())
        .expect_err("non-canonical emergency_pause key_id must be rejected first");
    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(
        !err.contains("strict bool"),
        "key-id mismatch path must not leak value-schema errors: {err}"
    );
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_replace_rejects_non_canonical_key_id_without_side_effects() {
    // Merge-gate guard: Replace action must enforce the same canonical key-id pinning.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            8_051,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace with non-canonical emergency_pause key_id must be rejected");

    assert!(err.contains("expected_id=7999"), "{err}");
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_path_is_immediate_and_non_cancellable() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param(8_000, 7999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let cancel_err = st
        .set_gov_param_with_action(
            8_001,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    // Failed cancel must be side-effect free on pause state and pending queues.
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let applied_unpause = st
        .set_gov_param(8_002, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(matches!(applied_unpause, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_noop_update_is_idempotent_after_pause() {
    // Merge-gate guard: repeated identical emergency_pause writes should be side-effect free.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(8_010, 7_999, "emergency_pause".into(), "true".into())
        .expect("initial pause=true write must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param(8_011, 7_999, "emergency_pause".into(), "true".into())
        .expect("noop pause=true write must succeed");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(first_ref, second_ref, "noop must not churn object version");
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_checked_replace_noop_is_idempotent() {
    // Merge-gate guard: Replace action on a non-sensitive emergency_pause value should
    // stay immediate and avoid version churn when value is unchanged.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            8_620,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("initial replace pause=true write must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply for non-sensitive replace"),
    };

    let second = st
        .set_gov_param_with_action(
            8_621,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("noop replace pause=true write must succeed");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply for non-sensitive replace"),
    };

    assert_eq!(
        first_ref, second_ref,
        "non-sensitive replace noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_cancel_scrubs_stale_pending_entry_even_when_unsupported() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: non-sensitive emergency_pause should never have
    // timelocked pending state; even unsupported Cancel attempts must scrub stale entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_650,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unsupported cancel must still scrub stale pending emergency_pause entries"
    );
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_skips_value_validation_but_stays_side_effect_free() {
    let mut st = StateStore::new();

    // Merge-gate guard: Cancel keeps parser bypass semantics (no bool validation) but must
    // remain side-effect free beyond stale pending cleanup.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_888,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            7_999,
            "emergency_pause".into(),
            "NOT_BOOL".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("cancel not supported for non-sensitive key"));
    assert!(
        !cancel_err.contains("invalid governance value"),
        "cancel path must not attempt value parsing for emergency_pause"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_cancel_wrong_key_id_is_rejected_without_scrubbing_state() {
    let mut st = StateStore::new();

    // Merge-gate guard: key_id mismatch must fail before any state cleanup/mutation,
    // even when legacy/corrupt pending emergency_pause data exists.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 77_777,
        },
    );

    let cancel_err = st
        .set_gov_param_with_action(
            8_651,
            8_000,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Cancel,
        )
        .unwrap_err();
    assert!(cancel_err.contains("expected_id=7999"), "{cancel_err}");

    let pending = st
        .pending_gov_update("emergency_pause")
        .expect("mismatched key_id path must not mutate pending state");
    assert_eq!(pending.key_id, 7_999);
    assert_eq!(pending.activate_at_height, 77_777);
    assert!(!st.is_emergency_paused());
}

#[test]
fn emergency_pause_checked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // but if a stale pending entry exists, checked-path apply must scrub it.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param(8_700, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "stale pending entry must be removed for non-sensitive emergency_pause"
    );
}

#[test]
fn emergency_pause_unchecked_path_clears_stale_pending_entry_if_present() {
    let mut st = StateStore::new();

    // Corrupt/legacy state simulation: emergency_pause should never be timelocked,
    // and unchecked-path writes must still scrub stale pending entries.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_888,
        },
    );

    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked emergency_pause apply must remove stale pending entry"
    );
}

#[test]
fn emergency_pause_unchecked_noop_is_idempotent_and_clears_stale_pending_entry() {
    let mut st = StateStore::new();

    let first_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("first unchecked pause write must succeed");
    assert!(st.is_emergency_paused());

    // Corrupt/legacy state simulation: stale pending residue must be scrubbed even
    // when the unchecked write is a noop.
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 88_999,
        },
    );

    let second_ref = st
        .set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked noop pause write must stay idempotent");

    assert_eq!(
        first_ref, second_ref,
        "unchecked noop emergency_pause write must not churn version"
    );
    assert!(st.is_emergency_paused());
    assert!(
        st.pending_gov_update("emergency_pause").is_none(),
        "unchecked noop must still remove stale emergency_pause pending entry"
    );
}

#[test]
fn emergency_pause_does_not_mutate_other_sensitive_pending_updates() {
    let mut st = StateStore::new();

    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(8_600, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 8_620);

    let pause_outcome = st
        .set_gov_param(8_601, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(matches!(pause_outcome, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("challenge_min_bond pending update must remain");
    assert_eq!(pending.key_id, 8_500);
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 8_620);
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_remains_immediate_without_pending_state() {
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_000,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    // Replace action must remain immediate and non-scheduling in both directions.
    let unapplied = st
        .set_gov_param_with_action(
            9_001,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_scrubs_stale_pending_entry() {
    // Merge-gate guard: Replace action must stay on the immediate non-sensitive path,
    // including cleanup of any legacy/corrupt queued emergency_pause timelock entry.
    let mut st = StateStore::new();
    st.pending_gov_updates.insert(
        "emergency_pause".into(),
        PendingGovParamUpdate {
            key_id: 7_999,
            key: "emergency_pause".into(),
            value: "true".into(),
            activate_at_height: 99_999,
        },
    );

    let applied = st
        .set_gov_param_with_action(
            9_004,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace action should apply immediately for emergency_pause");

    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_action_still_enforces_strict_bool_schema() {
    // Merge-gate guard: action variants must not bypass strict bool validation.
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_with_action(
            9_005,
            7_999,
            "emergency_pause".into(),
            "TRUE".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect_err("replace action must reject non-strict bool literal");
    assert!(err.contains("expected strict bool"));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_replace_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: Replace noop must stay immediate and avoid object-version churn.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_006,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("initial replace pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_007,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replace noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "replace noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_action_remains_immediate_without_pending_state() {
    // Merge-gate guard: explicit Enforce action must stay on the immediate path for
    // emergency pause and never route through timelock scheduling.
    let mut st = StateStore::new();

    let applied = st
        .set_gov_param_with_action(
            9_010,
            7999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());

    let unapplied = st
        .set_gov_param_with_action(
            9_011,
            7999,
            "emergency_pause".into(),
            "false".into(),
            GovPendingUpdateAction::Enforce,
        )
        .unwrap();
    assert!(matches!(unapplied, GovParamUpdateOutcome::Applied(_)));
    assert!(!st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_enforce_noop_is_idempotent_and_non_scheduling() {
    // Merge-gate guard: explicit Enforce noop must keep immediate semantics and avoid
    // object-version churn for emergency_pause.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param_with_action(
            9_011,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("initial enforce pause=true must apply immediately");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    let second = st
        .set_gov_param_with_action(
            9_012,
            7_999,
            "emergency_pause".into(),
            "true".into(),
            GovPendingUpdateAction::Enforce,
        )
        .expect("enforce noop pause=true must remain immediate and idempotent");
    let second_ref = match second {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("expected immediate apply"),
    };

    assert_eq!(
        first_ref, second_ref,
        "enforce noop must not churn object version"
    );
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn emergency_pause_does_not_bypass_sensitive_timelock_guards() {
    // Merge-gate guard: paused mode must not allow sensitive governance params
    // to skip the timelock state machine.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(8_500, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(9_200, 8_500, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };

    st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
        .unwrap();
    assert!(st.is_emergency_paused());

    let err = st
        .set_gov_param(9_205, 8_500, "challenge_min_bond".into(), "120".into())
        .expect_err("paused mode must not bypass sensitive timelock");
    assert!(err.contains("timelock active"), "{err}");

    let pending = st
        .pending_gov_update("challenge_min_bond")
        .expect("timelock pending update must remain intact while paused");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(pending.value, "120");
}

#[test]
fn emergency_pause_checked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param(9_100, 7999, "emergency_pause".into(), "true".into())
        .unwrap();

    let err = st
        .set_gov_param(9_101, 8000, "emergency_pause".into(), "false".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));

    // Confirm canonical key id still controls pause state.
    st.set_gov_param(9_102, 7999, "emergency_pause".into(), "false".into())
        .unwrap();
    assert!(!st.is_emergency_paused());
}

#[test]
fn non_sensitive_governance_noop_rejects_mismatched_key_id() {
    // Merge-gate guard: noop/idempotent path must not hide key-id drift for immediate keys.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(9_300, 6_001, "max_block_ms".into(), "500".into())
        .expect("seed max_block_ms must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("max_block_ms must remain immediate"),
    };

    let err = st
        .set_gov_param(9_301, 6_002, "max_block_ms".into(), "500".into())
        .expect_err("mismatched key-id noop must be rejected");
    assert!(err.contains("governance key id mismatch"), "{err}");

    let preserved = st
        .get_param(first_ref.id)
        .expect("canonical max_block_ms entry must remain readable");
    assert_eq!(preserved.key_id, 6_001);
    assert_eq!(preserved.value, "500");
    assert!(st.pending_gov_update("max_block_ms").is_none());
}

#[test]
fn governance_timelock_classification_merge_gate_keeps_emergency_pause_immediate() {
    // Exhaustive merge-gate guard for timelock classification: changing this table means
    // emergency pause semantics changed and tests/rollout should be reviewed explicitly.
    let expected_sensitive = [
        ("challenge_window_blocks", true),
        ("challenge_min_bond", true),
        ("challenge_success_bounty", true),
        ("min_worker_stake", true),
        ("challenge_min_bond_bounty_bps", true),
        ("challenge_min_bond_worker_stake_bps", true),
        ("resolve_authority", true),
        ("emergency_pause", false),
    ];

    let expected_sensitive_count = expected_sensitive.iter().filter(|(_, v)| *v).count();
    assert_eq!(
        GOV_SENSITIVE_KEYS.len(),
        expected_sensitive_count,
        "sensitive-key list changed; update timelock classification merge gate"
    );

    for (key, expected) in expected_sensitive {
        assert!(
            GOV_ALLOWED_KEYS.contains(&key),
            "timelock merge gate contains non-whitelisted key: {}",
            key
        );
        assert_eq!(
            is_sensitive_gov_param(key),
            expected,
            "governance sensitivity drifted for key: {}",
            key
        );
    }

    // Behavioral merge-gate: pause must remain immediate (never timelocked/scheduled).
    let mut st = StateStore::new();
    let outcome = st
        .set_gov_param(96_100, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause update");
    assert!(
        matches!(outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause must apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(st.is_emergency_paused());

    let unpause_outcome = st
        .set_gov_param(96_101, 7_999, "emergency_pause".into(), "false".into())
        .expect("unpause update");
    assert!(
        matches!(unpause_outcome, GovParamUpdateOutcome::Applied(_)),
        "emergency_pause=false must also apply immediately"
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
    assert!(!st.is_emergency_paused());
}

#[test]
fn governance_allowed_keys_schema_merge_gate_is_explicit() {
    // Exhaustive merge-gate guard for whitelist+schema safety. Any added/changed key
    // must update this table with an invalid sample that is expected to fail.
    let expected_invalid_samples = [
        ("max_block_ms", "9"),
        ("max_parallel_workers", "0"),
        ("min_worker_stake", "0"),
        ("challenge_min_bond", "0"),
        ("challenge_min_bond_bounty_bps", "100001"),
        ("challenge_min_bond_worker_stake_bps", "100001"),
        ("challenge_window_blocks", "99"),
        ("challenge_success_bounty", "-1"),
        ("resolve_authority", "   "),
        ("emergency_pause", "TRUE"),
        ("monetary_policy_tick_interval_blocks", "0"),
        ("monetary_policy_tick_cooldown_blocks", "0"),
        ("monetary_base_issuance_per_tick", "1000000000001"),
        ("monetary_base_burn_per_tick", "1000000000001"),
    ];

    assert_eq!(
        GOV_ALLOWED_KEYS.len(),
        expected_invalid_samples.len(),
        "governance allowed-key list changed; update schema merge gate"
    );

    let mut st = StateStore::new();
    for (i, (key, bad_value)) in expected_invalid_samples.iter().enumerate() {
        assert!(
            GOV_ALLOWED_KEYS.contains(key),
            "schema merge gate contains non-whitelisted key: {}",
            key
        );
        let key_id = if *key == "emergency_pause" {
            7_999
        } else {
            96_000 + i as u64
        };
        let err = st
            .set_gov_param_unchecked(key_id, (*key).into(), (*bad_value).into())
            .unwrap_err();
        assert!(
            err.contains("invalid governance value"),
            "expected schema rejection for key={}, got: {}",
            key,
            err
        );
    }
}

#[test]
fn governance_resolve_authority_rejects_reserved_or_placeholder_values() {
    let mut st = StateStore::new();

    for (i, bad_value) in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "Governance.Resolve_Authority",
        RESERVED_SYSTEM_AUTHORITY,
        "System",
        "authority,system",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Escrow",
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
        "TREASURY.CHALLENGE_FORFEITS",
        WORKER_SLASH_TREASURY_ACCOUNT,
        "Treasury.Worker_Slashes",
        "authority,treasury.challenge_escrow",
        "authority,Treasury.Challenge_Forfeits",
        "authority,treasury.worker_slashes",
        "authority ",
        "authority team",
        "authority\u{3000}team",
        "authority,",
        ",authority",
        "authority,,authority2",
        "authority,authority",
        "authority,Authority",
        "authority, authority2",
        "authority;authority2",
        "authority|authority2",
        "authority,authority2|authority3",
        "authority,authority2;authority3",
        "authority；authority2",
        "authority，authority2",
        "authority、authority2",
        "authority\u{0000}x",
        "authority,\u{0007}authority2",
    ]
    .iter()
    .enumerate()
    {
        let err = st
            .set_gov_param_unchecked(
                97_100 + i as u64,
                "resolve_authority".into(),
                (*bad_value).into(),
            )
            .expect_err("reserved/malformed resolve_authority must be rejected");
        assert!(
            err.contains("invalid governance value for resolve_authority"),
            "unexpected error for value {:?}: {}",
            bad_value,
            err
        );
    }
}

#[test]
fn governance_accepts_comma_separated_resolve_authority_members() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        97_500,
        "resolve_authority".into(),
        "authority,authority2".into(),
    )
    .expect("comma-separated resolve authority members should be accepted");
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority,authority2".to_string())
    );
}

#[test]
fn emergency_pause_toggles_preserve_challenge_escrow_conservation() {
    // Merge-gate guard: emergency pause is a control-plane brake only; it must never
    // mutate custody balances used by challenge escrow accounting.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 1_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 500);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_000, 7_999, "emergency_pause".into(), "true".into())
        .expect("checked pause write should apply immediately");
    st.set_gov_param(98_001, 7_999, "emergency_pause".into(), "false".into())
        .expect("checked unpause write should apply immediately");
    st.set_gov_param_unchecked(7_999, "emergency_pause".into(), "true".into())
        .expect("unchecked pause write should be accepted at canonical key id");

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.pending_gov_update("emergency_pause").is_none());
}

#[test]
fn governance_keysets_merge_gate_are_unique_and_subset_safe() {
    // Merge-gate: duplicate keys in static tables can silently weaken policy checks.
    let allowed_unique: std::collections::BTreeSet<&str> =
        GOV_ALLOWED_KEYS.iter().copied().collect();
    assert_eq!(
        allowed_unique.len(),
        GOV_ALLOWED_KEYS.len(),
        "GOV_ALLOWED_KEYS contains duplicate entries"
    );

    let sensitive_unique: std::collections::BTreeSet<&str> =
        GOV_SENSITIVE_KEYS.iter().copied().collect();
    assert_eq!(
        sensitive_unique.len(),
        GOV_SENSITIVE_KEYS.len(),
        "GOV_SENSITIVE_KEYS contains duplicate entries"
    );

    for key in &sensitive_unique {
        assert!(
            allowed_unique.contains(key),
            "sensitive key must also be whitelisted: {}",
            key
        );
    }

    assert!(
        !sensitive_unique.contains("emergency_pause"),
        "emergency_pause must remain immediate and never timelocked"
    );
}

#[test]
fn balance_debit_credit_works() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 15);
    assert_eq!(st.balance_of("challenger"), 15);

    st.debit_balance("challenger", 10).unwrap();
    assert_eq!(st.balance_of("challenger"), 5);

    let err = st.debit_balance("challenger", 6).unwrap_err();
    assert!(err.contains("insufficient balance"));

    st.credit_balance("challenger", 7).unwrap();
    assert_eq!(st.balance_of("challenger"), 12);
}

#[test]
fn balance_credit_overflow_rejected() {
    let mut st = StateStore::new();
    st.set_balance("treasury", u128::MAX - 1);

    let err = st.credit_balance("treasury", 2).unwrap_err();
    assert!(err.contains("balance overflow on credit"));
}

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

#[test]
fn wal_checkpoint_verification_picks_latest_valid() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };
    let h2 = e2.content_hash_hex();

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
}

#[test]
fn wal_checkpoint_verification_falls_back_on_chain_break() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some("wrong-prev".into()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
}

#[test]
fn wal_checkpoint_verification_falls_back_on_non_monotonic_height() {
    let e1 = WalMeta {
        height: 10,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        // Repeated height must terminate verification.
        height: 10,
        round: 1,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 10,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 10,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn wal_checkpoint_verification_is_height_ordered_even_if_checkpoint_list_is_not() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: true,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1),
    };
    let h2 = e2.content_hash_hex();

    // Intentionally unsorted input: height 2 checkpoint appears first.
    let checkpoints = vec![
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: h2,
        },
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: e1.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 2);
    assert_eq!(got.state_root_hex, "r2");
}

#[test]
fn wal_checkpoint_verification_stops_before_uncommitted_tail() {
    let e1 = WalMeta {
        height: 1,
        round: 0,
        proposal_hash: "p1".into(),
        committed: true,
        state_root_hex: "r1".into(),
        prev_hash_hex: None,
    };
    let h1 = e1.content_hash_hex();
    let e2 = WalMeta {
        height: 2,
        round: 0,
        proposal_hash: "p2".into(),
        committed: false,
        state_root_hex: "r2".into(),
        prev_hash_hex: Some(h1.clone()),
    };

    let checkpoints = vec![
        CheckpointMeta {
            height: 1,
            state_root_hex: "r1".into(),
            wal_entry_hash_hex: h1,
        },
        CheckpointMeta {
            height: 2,
            state_root_hex: "r2".into(),
            wal_entry_hash_hex: e2.content_hash_hex(),
        },
    ];

    let got = verify_wal_and_find_checkpoint(&checkpoints, &[e1, e2])
        .unwrap()
        .expect("checkpoint");
    assert_eq!(got.height, 1);
    assert_eq!(got.state_root_hex, "r1");
}

#[test]
fn policy_tick_triggers_on_interval_and_updates_monetary_state() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_001,
        "monetary_policy_tick_interval_blocks".into(),
        "3".into(),
    )
    .expect("set interval");
    st.set_gov_param_unchecked(
        9_002,
        "monetary_policy_tick_cooldown_blocks".into(),
        "3".into(),
    )
    .expect("set cooldown");
    st.set_gov_param_unchecked(9_003, "monetary_base_issuance_per_tick".into(), "15".into())
        .expect("set issuance");
    st.set_gov_param_unchecked(9_004, "monetary_base_burn_per_tick".into(), "4".into())
        .expect("set burn");

    assert!(st.policy_tick(2).is_none());
    let e1 = st.policy_tick(3).expect("tick at h=3");
    assert_eq!(e1.net_delta, 11);
    assert_eq!(e1.tick_count, 1);
    assert_eq!(e1.block_height, 3);
    assert_eq!(e1.cooldown_blocks, 3);
    assert_eq!(e1.interval_param_version, 1);
    assert_eq!(e1.cooldown_param_version, 1);
    assert!(
        st.policy_tick(3).is_none(),
        "same height must be idempotent"
    );

    let e2 = st.policy_tick(6).expect("tick at h=6");
    assert_eq!(e2.tick_count, 2);
    assert_eq!(e2.total_minted, 30);
    assert_eq!(e2.total_burned, 8);
    assert_eq!(e2.net_issuance, 22);
}

#[test]
fn governance_param_schema_rejects_invalid_monetary_policy_bounds() {
    let mut st = StateStore::new();
    let err_interval = st
        .set_gov_param_unchecked(
            9_010,
            "monetary_policy_tick_interval_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_interval.contains("out of range"));

    let err_cooldown = st
        .set_gov_param_unchecked(
            9_011,
            "monetary_policy_tick_cooldown_blocks".into(),
            "0".into(),
        )
        .unwrap_err();
    assert!(err_cooldown.contains("out of range"));

    let err_issuance = st
        .set_gov_param_unchecked(
            9_012,
            "monetary_base_issuance_per_tick".into(),
            "1000000000001".into(),
        )
        .unwrap_err();
    assert!(err_issuance.contains("out of range"));

    let err_burn = st
        .set_gov_param_unchecked(9_013, "monetary_base_burn_per_tick".into(), "-1".into())
        .unwrap_err();
    assert!(err_burn.contains("expected u64"));
}

#[test]
fn policy_tick_fail_closed_when_monetary_params_incomplete() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_020,
        "monetary_policy_tick_interval_blocks".into(),
        "2".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_021, "monetary_base_issuance_per_tick".into(), "1".into())
        .unwrap();
    st.set_gov_param_unchecked(9_022, "monetary_base_burn_per_tick".into(), "0".into())
        .unwrap();

    assert!(!st.should_trigger_policy_tick(2));
    assert!(st.policy_tick(2).is_none());
    assert_eq!(st.monetary_state().tick_count, 0);
}

#[test]
fn policy_tick_cooldown_throttles_repeated_schedule_points() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        9_030,
        "monetary_policy_tick_interval_blocks".into(),
        "2".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(
        9_031,
        "monetary_policy_tick_cooldown_blocks".into(),
        "4".into(),
    )
    .unwrap();
    st.set_gov_param_unchecked(9_032, "monetary_base_issuance_per_tick".into(), "5".into())
        .unwrap();
    st.set_gov_param_unchecked(9_033, "monetary_base_burn_per_tick".into(), "1".into())
        .unwrap();

    assert!(st.policy_tick(2).is_some());
    assert!(st.policy_tick(4).is_none(), "cooldown should block h=4");
    assert!(st.policy_tick(6).is_some(), "cooldown should allow h=6");
}
