use super::*;
use crate::operator_continuous_test_support::{allocation, delegation, signed_allocation};
#[test]
fn mode4_recipient_both_signatures_external_expected_and_allocator_latest_are_mandatory() {
    let body = allocation("search");
    let (raw, mut outside) = signed_allocation(&body);
    assert!(authenticate(&raw, &outside, 1).is_ok());
    outside.latest_allocator_digest = "ff".repeat(32);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let (raw, mut outside) = signed_allocation(&body);
    outside.expected.claim.parent = "ee".repeat(32);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let (raw, outside) = signed_allocation(&body);
    let mut wire: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    wire["task_signature"] = serde_json::json!("00".repeat(64));
    let raw = serde_json::to_vec(&wire).unwrap();
    let mut outside = outside;
    outside.expected_envelope_sha256 = digest(&raw);
    assert!(authenticate(&raw, &outside, 1).is_err());
}
#[test]
fn mode4_recipient_exact_task_class_generation_and_registry_delegation_do_not_project_hashes() {
    let body = allocation("search");
    let (raw, outside) = signed_allocation(&body);
    let valid = authenticate(&raw, &outside, 1).unwrap();
    assert!(valid.check_delegation(&delegation(1), 1).is_ok());
    let mut d = delegation(1);
    d.declared_binding.task.lease_sha256 = "aa".repeat(32);
    assert!(valid.check_delegation(&d, 1).is_err());
    d = delegation(1);
    d.recipient_nodes = vec!["aa".repeat(32)];
    assert!(valid.check_delegation(&d, 1).is_err());
    let mut b = body.clone();
    b.claim.generation = 1;
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
    b = body;
    b.claim.instance_class = "zero".into();
    b.claim.operation = operation_id(&b.identity, &b.claim).unwrap();
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
}
#[test]
fn mode4_receiver_origin_is_required_exact_and_not_a_local_search_claim() {
    let body = allocation("receiver-validation");
    let (raw, outside) = signed_allocation(&body);
    assert!(authenticate(&raw, &outside, 1).is_ok());
    let mut b = body.clone();
    b.origin = None;
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let mut b = body;
    if let Some(Origin::ClosedFixture { generation, .. }) = &mut b.origin {
        *generation = 1;
    }
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let mut b = allocation("search");
    b.origin = allocation("receiver-validation").origin;
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
}
#[test]
fn mode4_declared_material_profile_and_preprocessing_remain_explicit_unqualified() {
    let mut b = allocation("search");
    b.declared_binding.task.field_modulus = 2013265921;
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let mut b = allocation("search");
    b.claim.allocation.reuse_uses = 1;
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
    let mut b = allocation("search");
    b.declared_binding.cost_class = "reported-preprocessed-reuse".into();
    let (raw, outside) = signed_allocation(&b);
    assert!(authenticate(&raw, &outside, 1).is_err());
}
