use super::*;

#[test]
fn governance_validator_rejects_unknown_key_fail_closed() {
    let err = crate::governance_ops::validate_gov_param_value("definitely_unknown_key", "123")
        .expect_err("unknown governance key must fail closed");
    assert!(err.contains("governance key not allowed"), "{err}");
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
