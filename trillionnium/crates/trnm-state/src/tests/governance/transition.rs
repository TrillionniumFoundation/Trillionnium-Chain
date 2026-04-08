use super::*;

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
