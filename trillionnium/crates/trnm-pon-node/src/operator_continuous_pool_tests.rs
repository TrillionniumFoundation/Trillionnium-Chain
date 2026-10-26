//! Typed/source mechanisms only. These unsigned PNX-shaped bodies are not Native evidence.
use super::*;
use crate::operator_continuous_test_support::{allocation, signed_allocation};
fn raw(n: u8) -> Vec<u8> {
    let mut v = vec![n; 159];
    v[..4].copy_from_slice(b"PNX1");
    v
}
fn selection() -> Selection {
    Selection {
        schema: "restricted-continuous-pool-selection-v1".into(),
        operation: "11".repeat(32),
        purpose: Purpose::SubmitBundle,
        parent: "12".repeat(32),
        generation: 0,
        native_task: "10".repeat(32),
        task_binding: declared_binding_digest(&crate::operator_continuous_test_support::binding())
            .unwrap(),
        pool_context: "13".repeat(32),
        limits_sha256: "14".repeat(32),
        exact_new_transactions_sha256: crate::operator_mining_policy::transactions_sha256(&[raw(
            1,
        )])
        .unwrap(),
        retained_groups: vec![RetainedGroup {
            group: "15".repeat(32),
            original_admission_operation: "16".repeat(32),
            exact_transactions_sha256: crate::operator_mining_policy::transactions_sha256(&[
                raw(2),
                raw(3),
            ])
            .unwrap(),
        }],
        exact_selected_transactions_sha256: None,
        exact_prune_group: None,
        max_records: None,
        max_bytes: None,
    }
}
fn verified(mut s: Selection) -> VerifiedSelection {
    let mut body = allocation(s.purpose.claim_purpose());
    body.claim.payload = s.payload_sha256().unwrap();
    body.claim.operation =
        crate::operator_continuous_recipient::operation_id(&body.identity, &body.claim).unwrap();
    s.operation = body.claim.operation.clone();
    let (wire, outside) = signed_allocation(&body);
    let permission =
        crate::operator_continuous_recipient::authenticate(&wire, &outside, 1).unwrap();
    VerifiedSelection::authenticate(&s, &permission).unwrap()
}
#[test]
fn mode5_pool_selection_has_no_operation_hash_cycle_and_full_signed_context_is_required() {
    let mut s = selection();
    let old = s.payload_sha256().unwrap();
    s.operation = "ee".repeat(32);
    assert_eq!(s.payload_sha256().unwrap(), old);
    let valid = verified(s.clone());
    assert_eq!(valid.body().payload_sha256().unwrap(), old);
    let mut changed = valid.body().clone();
    changed.generation += 1;
    assert_ne!(changed.payload_sha256().unwrap(), old);
    changed = valid.body().clone();
    changed.retained_groups[0].original_admission_operation = "ef".repeat(32);
    assert_ne!(changed.payload_sha256().unwrap(), old);
    changed = valid.body().clone();
    let mut body = allocation("search");
    body.claim.payload = old;
    body.claim.operation =
        crate::operator_continuous_recipient::operation_id(&body.identity, &body.claim).unwrap();
    changed.operation = body.claim.operation.clone();
    let (wire, outside) = signed_allocation(&body);
    let permission =
        crate::operator_continuous_recipient::authenticate(&wire, &outside, 1).unwrap();
    assert!(VerifiedSelection::authenticate(&changed, &permission).is_err());
}
#[test]
fn mode5_retained_original_operation_and_whole_ordered_raws_are_separate_from_new_bundle() {
    let mut v = verified(selection());
    assert!(v.bind_new(&[raw(2)]).is_err());
    v.bind_new(&[raw(1)]).unwrap();
    assert!(v.all_retained_bound().is_err());
    assert!(v
        .bind_retained([0x15; 32], &"17".repeat(32), &[raw(2), raw(3)])
        .is_err());
    assert!(v
        .bind_retained([0x15; 32], &"16".repeat(32), &[raw(3), raw(2)])
        .is_err());
    assert!(v
        .bind_retained([0x15; 32], &"16".repeat(32), &[raw(2)])
        .is_err());
    v.bind_retained([0x15; 32], &"16".repeat(32), &[raw(2), raw(3)])
        .unwrap();
    v.all_retained_bound().unwrap();
    assert!(v.check_bound_group(&[raw(1)]).is_err());
    assert!(v.check_prefix(&[raw(2), raw(3), raw(1)]).is_ok());
    assert!(v.check_prefix(&[raw(2), raw(4)]).is_err());
    // This is only a raw authorization gate. Original typed order/M06 remain mandatory.
    assert!(v.check_new_bundle(&[raw(1), raw(2)]).is_err());
}
#[test]
fn mode5_all_seven_pool_commands_reject_unknown_fields_and_cross_purpose() {
    for wire in [
        r#"{"command":"reconcile","refund":true}"#,
        r#"{"command":"status","operation":"self-issued"}"#,
        r#"{"command":"submit-bundle","transactions":[],"skip_m06":true}"#,
        r#"{"command":"prune","group":"00","refund":true}"#,
    ] {
        assert!(serde_json::from_str::<Command>(wire).is_err());
    }
    let command: Command = serde_json::from_str(r#"{"command":"reconcile"}"#).unwrap();
    assert!(command.check_selection(&selection()).is_err());
    let v = verified(selection());
    assert!(v.check_internal_command("submit-bundle", &[raw(1)]).is_ok());
    assert!(v.check_internal_command("enable-pool", &[raw(1)]).is_err());
    assert!(v.check_internal_command("reconcile", &[]).is_ok());
}
#[test]
fn mode5_selection_rejects_incomplete_duplicate_or_wrong_signed_batch_prune_parameters() {
    let mut s = selection();
    s.retained_groups.push(s.retained_groups[0].clone());
    assert!(s.payload_sha256().is_err());
    s = selection();
    s.exact_selected_transactions_sha256 = Some("ff".repeat(32));
    assert!(s.payload_sha256().is_err());
    s = selection();
    s.purpose = Purpose::MiningBatch;
    s.max_records = Some(257);
    s.max_bytes = Some(524288);
    assert!(s.payload_sha256().is_err());
    s.max_records = Some(256);
    s.max_bytes = Some(524289);
    assert!(s.payload_sha256().is_err());
    s = selection();
    s.purpose = Purpose::Prune;
    assert!(s.payload_sha256().is_err());
}
#[test]
fn mode5_batch_json_retains_exact_parent_generation_groups_and_complete_raws() {
    let batch = crate::PoolBatch {
        parent: [1; 32],
        generation: 7,
        context: [2; 32],
        preview_miner: [3; 32],
        transactions: vec![raw(1)],
        groups: vec![[4; 32]],
        typed_gate_admissions: 1,
    };
    let wire = BatchInput::from_actual(batch);
    let actual = wire.actual().unwrap();
    assert_eq!(actual.parent, [1; 32]);
    assert_eq!(actual.generation, 7);
    assert_eq!(actual.transactions, vec![raw(1)]);
    assert_eq!(actual.groups, vec![[4; 32]]);
    let mut bad = wire;
    bad.transactions[0] = bad.transactions[0].to_uppercase();
    assert!(bad.actual().is_err());
}
