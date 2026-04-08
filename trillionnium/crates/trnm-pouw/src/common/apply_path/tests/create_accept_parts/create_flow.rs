use super::*;

#[test]
fn create_task_defaults_proof_type_to_fraud() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 1001, "alice".into(), 10).unwrap();
    let task = st.get_task(r1.id).unwrap();
    // Since ProofType::Fraud is the default (0/first variant usually or Default impl), verify it.
    // We need to access ProofType via crate root re-export or super import.
    // The `use super::*;` pulls in `trnm_types` if it is used in super.
    // But `trnm_types` is used via `use trnm_types::{...}` in super.
    // I should check if `trnm_types` crate is available as `trnm_types`.
    // It is a dependency, so `trnm_types::ProofType` should work if I add `use trnm_types::ProofType;` or similar.
    // Or simply check equality if I import ProofType.
    assert_eq!(task.proof_type, trnm_types::ProofType::Fraud);
}
#[test]
fn full_happy_path_to_completed() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let r1 = apply_create_task(&mut st, 42, "alice".into(), 100).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(42, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    set_resolve_authority(&mut st, "authority,authority2");
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("first resolver should stage multisig approval");
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();

    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Completed);
}
