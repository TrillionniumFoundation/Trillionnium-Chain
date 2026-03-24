use super::*;

#[test]
fn node_resolve_multisig_first_approval_persists_and_second_finalizes() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_500,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let (r5, _, _) = challenged_task_fixture(&mut st, 8101);

    let first = apply_one(
        &mut st,
        MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-a".into(),
        },
        130,
    );
    assert!(matches!(
        first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
        Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
    ));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Challenged);

    apply_one(
        &mut st,
        MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-b".into(),
        },
        131,
    )
    .expect("second signer should finalize through node-facing path");
    assert_eq!(st.pending_resolve_approval(r5.id), None);
    assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Slashed);
    assert!(st.get_ref(r5.id).unwrap().version > r5.version);
}
