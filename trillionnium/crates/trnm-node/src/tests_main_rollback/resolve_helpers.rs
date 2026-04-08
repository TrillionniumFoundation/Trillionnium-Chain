use super::*;

#[test]
fn verified_signer_for_multisig_resolve_uses_actual_resolver_member() {
    let mut st = StateStore::new();
    st.set_gov_param_bootstrap_unchecked(
        9_501,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .unwrap();
    let tx = MockTx::Resolve {
        task_id: 42,
        slash_worker: false,
        resolver: "authority-b".into(),
    };
    assert_eq!(verified_signer_of(&st, &tx), "authority-b");
}

#[test]
fn staged_resolve_approval_uses_distinct_event_type() {
    let tx = MockTx::Resolve {
        task_id: 7,
        slash_worker: true,
        resolver: "authority-a".into(),
    };
    assert_eq!(
        event_type_for_apply_outcome(&tx, Some("resolve_approval_staged")),
        "resolve_approval_staged"
    );
    assert_eq!(event_type_for_apply_outcome(&tx, None), "resolve");
}

#[test]
fn resolve_challenger_fallback_does_not_alias_resolver() {
    let tx = MockTx::Resolve {
        task_id: 9,
        slash_worker: false,
        resolver: "authority-b".into(),
    };
    assert_eq!(challenger_of(&tx), None);
}
