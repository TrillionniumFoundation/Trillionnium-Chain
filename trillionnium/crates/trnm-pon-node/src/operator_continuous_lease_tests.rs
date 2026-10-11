//! Protocol-shaped lease mechanisms; not Native/State/source evidence.
use super::*;
pub(crate) fn fixture() -> (DeclaredBinding, DeclaredBinding, LeaseEdge) {
    let mut lease = DemandLeaseV2 {
        slot: 0,
        purpose: trnm_protocol::qualified_work_task::TaskPurpose::Maintenance,
        network: [1; 32],
        parameters: [2; 32],
        demand_id: [0; 32],
        requester: [3; 32],
        source: [4; 32],
        source_record: [5; 32],
        authorization_scope: [6; 32],
        availability_manifest: [7; 32],
        availability_root: [8; 32],
        generation: 1,
        revision: 1,
        not_before: 0,
        expires: 100,
        available_until: 200,
        cost_class: 1,
    };
    lease.demand_id = lease.derived_demand_id();
    let old_raw = lease.encode().unwrap();
    lease.revision = 2;
    lease.expires = 200;
    lease.available_until = 300;
    let new_raw = lease.encode().unwrap();
    let mut old = crate::operator_continuous_test_support::binding();
    old.task.lease_sha256 = crate::operator_task_policy::digest_bytes(&old_raw);
    let mut new = old.clone();
    new.task.lease_sha256 = crate::operator_task_policy::digest_bytes(&new_raw);
    let edge = LeaseEdge {
        schema: "restricted-continuous-lease-edge-v1".into(),
        actual_parent: "12".repeat(32),
        actual_generation: 1,
        native_task: old.task.native_task.clone(),
        old_task_binding: declared_binding_digest(&old).unwrap(),
        new_task_binding: declared_binding_digest(&new).unwrap(),
        old_complete_lease: hex::encode(old_raw),
        new_complete_lease: hex::encode(new_raw),
        renewal_packet_sha256: crate::operator_task_policy::digest_bytes(
            b"actual retained packet fixture",
        ),
        new_registry2_declaration_digest: "13".repeat(32),
    };
    (old, new, edge)
}
#[test]
fn mode5_lease_edge_only_changes_complete_lease_and_exact_one_revision() {
    let (old, new, edge) = fixture();
    assert!(edge.check_declarations(&old, &new).is_ok());
    let mut changed = new.clone();
    changed.instance_class = "zero".into();
    assert!(edge.check_declarations(&old, &changed).is_err());
    changed = new.clone();
    changed.task.b_sha256 = "ff".repeat(32);
    assert!(edge.check_declarations(&old, &changed).is_err());
    changed = new.clone();
    changed.task.model_material = "ff".repeat(32);
    assert!(edge.check_declarations(&old, &changed).is_err());
    let mut bad = edge.clone();
    let mut lease = DemandLeaseV2::decode(&hex::decode(&bad.new_complete_lease).unwrap()).unwrap();
    lease.revision = 3;
    bad.new_complete_lease = hex::encode(lease.encode().unwrap());
    changed = new;
    changed.task.lease_sha256 =
        crate::operator_task_policy::digest_bytes(&hex::decode(&bad.new_complete_lease).unwrap());
    bad.new_task_binding = declared_binding_digest(&changed).unwrap();
    assert!(bad.check_declarations(&old, &changed).is_err());
}
#[test]
fn mode5_lease_edge_requires_actual_parent_generation_and_whole_original_bytes() {
    let (_old, _new, edge) = fixture();
    let old = hex::decode(&edge.old_complete_lease).unwrap();
    let new = hex::decode(&edge.new_complete_lease).unwrap();
    let packet = b"actual retained packet fixture";
    assert!(edge.check_actual([0x12; 32], 1, &old, &new, packet).is_ok());
    assert!(edge
        .check_actual([0x12; 32], 2, &old, &new, packet)
        .is_err());
    assert!(edge
        .check_actual([0x11; 32], 1, &old, &new, packet)
        .is_err());
    assert!(edge
        .check_actual([0x12; 32], 1, &new, &old, packet)
        .is_err());
    assert!(edge
        .check_actual([0x12; 32], 1, &old, &new, b"different packet")
        .is_err());
}
#[test]
fn mode5_lease_edge_forbids_duplicate_or_unknown_json_fields_and_partial_lease() {
    let (_, _, mut edge) = fixture();
    let mut value = serde_json::to_value(&edge).unwrap();
    value["refund"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LeaseEdge>(value).is_err());
    let full = serde_json::to_string(&edge).unwrap();
    let duplicated = full.replacen('{', r#"{"actual_generation":1,"#, 1);
    assert!(serde_json::from_str::<LeaseEdge>(&duplicated).is_err());
    edge.new_complete_lease
        .truncate(edge.new_complete_lease.len() - 2);
    assert!(edge.payload().is_err());
}
