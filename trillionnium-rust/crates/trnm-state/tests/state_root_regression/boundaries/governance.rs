use super::*;

#[test]
fn governance_proposal_status_transition_should_affect_state_root_and_match_equivalent_update_path()
{
    let proposal = GovProposalObject {
        proposal_id: 9_002,
        title: "Raise challenge success bounty".into(),
        proposer: "governance.alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    let mut transitioned = StateStore::new();
    let mut updated = StateStore::new();

    let transitioned_ref = transitioned.put_proposal_new(proposal.clone()).unwrap();
    let updated_ref = updated.put_proposal_new(proposal).unwrap();
    let baseline_root = transitioned.state_root();
    assert_eq!(
        baseline_root,
        updated.state_root(),
        "sanity: identical baseline proposal states should hash identically"
    );

    transitioned
        .transition_proposal_status(transitioned_ref, GovProposalStatus::Voting)
        .expect("proposal status transition should succeed");

    let mut manually_updated = updated
        .get_proposal(9_002)
        .expect("baseline proposal snapshot should exist");
    manually_updated.status = GovProposalStatus::Voting;
    updated
        .update_proposal(updated_ref, manually_updated)
        .expect("equivalent manual proposal status update should succeed");

    let transitioned_root = transitioned.state_root();
    assert_ne!(
        transitioned_root, baseline_root,
        "state_root should incorporate governance proposal status so draft and voting states cannot hash identically"
    );
    assert_eq!(
        transitioned_root,
        updated.state_root(),
        "equivalent proposal status transitions should produce the same deterministic root regardless of whether they use the transition helper or direct update path"
    );
}
#[test]
fn governance_proposal_title_and_proposer_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_003,
            title: "ab".into(),
            proposer: "c".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .unwrap();
    state_b
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_003,
            title: "a".into(),
            proposer: "bc".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .unwrap();

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame governance proposal title and proposer so field-boundary collisions cannot hash identically"
    );
}
#[test]
fn governance_proposal_version_must_affect_state_root_even_for_noop_payload_update() {
    let proposal = GovProposalObject {
        proposal_id: 9_004,
        title: "Raise challenge timeout".into(),
        proposer: "governance.alice".into(),
        status: GovProposalStatus::Draft,
        version: 1,
    };

    let mut baseline = StateStore::new();
    let mut updated = StateStore::new();

    baseline.put_proposal_new(proposal.clone()).unwrap();
    let updated_ref = updated.put_proposal_new(proposal).unwrap();
    let root_before = updated.state_root();

    let unchanged_payload = updated
        .get_proposal(9_004)
        .expect("proposal snapshot should exist before noop update");
    updated
        .update_proposal(updated_ref, unchanged_payload)
        .expect("noop payload update should still advance the stored proposal version");

    let root_after = updated.state_root();
    assert_ne!(
        root_after, root_before,
        "state_root must include governance proposal version so a no-op payload rewrite cannot hash identically to the original stored object"
    );
    assert_ne!(
        root_after,
        baseline.state_root(),
        "equivalent proposal payloads with different canonical stored versions must not share a state root"
    );
}
#[test]
fn governance_proposal_id_must_affect_state_root_even_when_other_payload_matches() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_005,
            title: "Raise fraud bond".into(),
            proposer: "governance.alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .expect("first governance proposal insertion should succeed");
    state_b
        .put_proposal_new(GovProposalObject {
            proposal_id: 9_006,
            title: "Raise fraud bond".into(),
            proposer: "governance.alice".into(),
            status: GovProposalStatus::Draft,
            version: 1,
        })
        .expect("second governance proposal insertion should succeed");

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root must include governance proposal_id so otherwise identical proposal payloads in distinct canonical slots cannot hash identically"
    );
}
#[test]
fn applied_gov_param_string_field_boundaries_should_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_gov_param(
        113,
        Some(GovParamObject {
            key_id: 113,
            key: "ab".into(),
            value: "c".into(),
            version: 1,
        }),
    );
    state_b.restore_gov_param(
        113,
        Some(GovParamObject {
            key_id: 113,
            key: "a".into(),
            value: "bc".into(),
            version: 1,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "state_root should length-frame applied governance param key and value so field-boundary collisions cannot hash identically"
    );
}
#[test]
fn applied_gov_param_version_must_affect_state_root_even_when_key_and_value_match() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 1,
        }),
    );
    state_b.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 2,
        }),
    );

    let root_a = state_a.state_root();
    let root_b = state_b.state_root();
    assert_ne!(
        root_a, root_b,
        "applied governance param version must contribute to state_root so identical key/value payloads at different canonical object versions cannot hash identically"
    );

    state_b.restore_gov_param(
        114,
        Some(GovParamObject {
            key_id: 114,
            key: "max_parallel_workers".into(),
            value: "8".into(),
            version: 1,
        }),
    );

    assert_eq!(
        state_b.state_root(),
        root_a,
        "restoring the original applied governance param version should rewind the deterministic root exactly"
    );
}
#[test]
fn pending_gov_update_key_string_boundaries_must_affect_state_root() {
    let mut state_a = StateStore::new();
    let mut state_b = StateStore::new();

    state_a.restore_pending_gov_update(
        "ab",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "ab".to_string(),
            value: "c".to_string(),
            activate_at_height: 1_020,
        }),
    );
    state_b.restore_pending_gov_update(
        "a",
        Some(PendingGovParamUpdate {
            key_id: 7_202,
            key: "a".to_string(),
            value: "bc".to_string(),
            activate_at_height: 1_020,
        }),
    );

    assert_ne!(
        state_a.state_root(),
        state_b.state_root(),
        "pending governance key/value strings must be length-framed in state_root so field-boundary collisions cannot hash identically"
    );
}
