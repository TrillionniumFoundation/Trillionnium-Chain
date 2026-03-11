use trnm_state::*;

#[test]
fn pending_gov_updates_should_affect_state_root() {
    let mut st1 = StateStore::new();
    let st2 = StateStore::new();

    // Base states are identical
    assert_eq!(st1.state_root(), st2.state_root());

    // Add a pending update to st1 only.
    st1.set_gov_param(1_000, 7_301, "challenge_min_bond".to_string(), "120".to_string())
        .unwrap();

    // Roots should now differ because of pending_gov_updates.
    assert_ne!(
        st1.state_root(),
        st2.state_root(),
        "State root should incorporate pending governance updates"
    );
}

#[test]
fn restore_pending_resolve_approval_roundtrip_preserves_state_root() {
    let mut staged = StateStore::new();
    staged
        .stage_or_confirm_resolve_approval(
            42,
            7,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();

    let staged_root = staged.state_root();
    let snapshot = staged.pending_resolve_approval_snapshot(42);

    staged.clear_pending_resolve_approval(42);
    assert_eq!(
        staged.state_root(),
        StateStore::new().state_root(),
        "clearing pending resolve approval should restore empty baseline"
    );

    staged.restore_pending_resolve_approval(42, snapshot);
    assert_eq!(
        staged.state_root(),
        staged_root,
        "restoring pending resolve approval snapshot must reproduce original state root"
    );
}
