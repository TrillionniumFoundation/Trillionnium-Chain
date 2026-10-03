use super::*;
use crate::operator_continuous_test_support::{
    allocation, binding, identity, signed, signed_allocation,
};
pub(crate) fn inputs() -> Inputs {
    let body = allocation("parent-reconcile");
    let (raw, authority) = signed_allocation(&body);
    let view = TaskView {
        schema: "restricted-continuous-task-view-v1".into(),
        identity: identity(),
        sequence: 1,
        previous_digest: None,
        actual_parent: body.claim.parent,
        actual_generation: 0,
        declared_binding: binding(),
        allocation_envelopes: vec![sha(&raw)],
        searches: Vec::new(),
        allowed_transactions: vec!["aa".repeat(32)],
        issued_ns: 1,
        expires_ns: 2,
        revoked: false,
    };
    let (raw_view, h) = signed(VIEW_DOMAIN, &view);
    let outside = ViewAuthority {
        identity: identity(),
        expected: view,
        envelope_sha256: sha(&raw_view),
        latest_sequence: 1,
        latest_digest: h,
    };
    Inputs {
        raw_view,
        view_authority: outside,
        raw_budget: None,
        budget_authority: None,
        allocations: vec![SignedAllocationInput { raw, authority }],
        journal_path: PathBuf::from("/unqualified-test-journal"),
        expected_uid: rustix::process::geteuid().as_raw(),
        expected_journal: Anchor::empty(),
        materials: Vec::new(),
    }
}
#[test]
fn mode4_view_authenticates_selected_allocations_before_any_catalog_read() {
    let input = inputs();
    assert!(authenticate(&input, 1).is_ok());
    assert!(authenticate(&input, 2).is_err());
    let mut input = inputs();
    input.view_authority.latest_sequence = 2;
    assert!(authenticate(&input, 1).is_err());
    let mut input = inputs();
    input.allocations[0]
        .authority
        .expected
        .identity
        .recipient_node = "ee".repeat(32);
    assert!(authenticate(&input, 1).is_err());
}
#[test]
fn mode4_protected_launch_keys_and_nested_authorities_cannot_self_authorize() {
    let i = identity();
    let input = inputs();
    assert!(validate_protected_inputs(
        &input,
        &i.registry_key,
        &i.task_key,
        &i.source_commit,
        &i.node_policy_source,
        &i.registry2_package
    )
    .is_ok());
    assert!(validate_protected_inputs(
        &input,
        &"ee".repeat(32),
        &i.task_key,
        &i.source_commit,
        &i.node_policy_source,
        &i.registry2_package
    )
    .is_err());
    let mut input = inputs();
    input.allocations[0].authority.identity.operator = "ee".repeat(32);
    assert!(validate_protected_inputs(
        &input,
        &i.registry_key,
        &i.task_key,
        &i.source_commit,
        &i.node_policy_source,
        &i.registry2_package
    )
    .is_err());
}
#[test]
fn mode4_linked_view_keeps_full_task_and_epoch_cancel_cannot_reissue_old_view() {
    let old = authenticate(&inputs(), 1).unwrap();
    let mut next = authenticate(&inputs(), 1).unwrap();
    next.body.sequence = 2;
    next.body.previous_digest = Some(old.digest.clone());
    assert!(next.next(&old));
    next.body.declared_binding.task.lease_sha256 = "ee".repeat(32);
    assert!(!next.next(&old));
    let epoch = Arc::new(AtomicU64::new(1));
    let permission = old.allocations[0].clone();
    let permit = Permit {
        view: Arc::new(old),
        allocation: permission,
        epoch: epoch.clone(),
        expected_epoch: 1,
        unavailable: Arc::new(AtomicBool::new(false)),
    };
    epoch.store(2, Ordering::Release);
    assert_eq!(permit.progress(), Err(PolicyError::CpuUnknown));
}
#[test]
fn mode4_catalog_permission_is_not_material_or_classification_evidence() {
    let input = inputs();
    let view = Arc::new(authenticate(&input, 1).unwrap());
    let permit = Permit {
        allocation: view.allocations[0].clone(),
        view,
        epoch: Arc::new(AtomicU64::new(1)),
        expected_epoch: 1,
        unavailable: Arc::new(AtomicBool::new(false)),
    };
    assert!(verify_catalog(&input, &permit, &|| Ok(())).is_err());
}

pub(crate) fn mechanism_view() -> VerifiedView {
    authenticate(&inputs(), 1).unwrap()
}
pub(crate) fn mechanism_catalog() -> HeldCatalog {
    HeldCatalog {
        rows: Vec::new(),
        roles: Vec::new(),
        catalog_sha256: "11".repeat(32),
    }
}

#[test]
fn mode4_duplicate_purpose_payload_is_not_a_second_selectable_operation() {
    let mut input = inputs();
    let mut second = allocation("parent-reconcile");
    second.claim.operation_nonce = "bb".repeat(32);
    second.claim.operation =
        crate::operator_continuous_recipient::operation_id(&second.identity, &second.claim)
            .unwrap();
    let (raw, authority) = signed_allocation(&second);
    input
        .allocations
        .push(SignedAllocationInput { raw, authority });
    let mut view = input.view_authority.expected.clone();
    view.allocation_envelopes = input.allocations.iter().map(|a| sha(&a.raw)).collect();
    view.allocation_envelopes.sort();
    let (raw, h) = signed(VIEW_DOMAIN, &view);
    input.raw_view = raw;
    input.view_authority.expected = view;
    input.view_authority.latest_digest = h;
    input.view_authority.envelope_sha256 = sha(&input.raw_view);
    assert!(authenticate(&input, 1).is_err());
}
