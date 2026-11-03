
#[test]
fn maintenance_recovers_signed_task_registration_and_policy_confirmation_after_revoke() {
    use trnm_protocol::qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2}, TaskPurpose,
    };
    use trnm_crypto_primitives::{pon_work, qualified_work_task::derive_matrices};

    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 2).unwrap();
    let old_task = bootstrap.signed.manifest.matrix_task;
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let revocation_tx = signed(&settings, 1, 1, 20, revoke.encode().unwrap());
    mine(&mut node, 1, vec![revocation_tx]);
    assert!(node.lifecycle_task_lease(node.active().unwrap().0, old_task, 2).is_err());

    // Fresh real signed requester and source statements, not a renewed or
    // fabricated old permission. The sole work source for this block is the
    // genesis maintenance task, with zero useful-output credit.
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let mut successor: DemandLeaseV2 = bootstrap.lease.clone();
    successor.slot = 1;
    successor.generation = 2;
    successor.purpose = TaskPurpose::InferenceContraction;
    successor.requester = development_public(2).unwrap();
    successor.not_before = 2;
    successor.expires = 1002;
    successor.available_until = 1102;
    successor.demand_id = successor.derived_demand_id();
    let mut manifest = bootstrap.signed.manifest;
    manifest.purpose = successor.purpose;
    manifest.source = successor.source;
    manifest.demand_id = successor.demand_id;
    manifest.source_record = successor.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[&model]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&input]);
    manifest.matrix_task = pon_work::task_id(&a, &b).unwrap();
    manifest.availability_manifest = successor.availability_manifest;
    manifest.availability_root = successor.availability_root;
    manifest.authorization_scope = successor.authorization_scope;
    manifest.withdrawal_head = successor.withdrawal_frontier().unwrap();
    manifest.demand_nonce = 1;
    manifest.not_before = successor.not_before;
    manifest.expires = successor.expires;
    manifest.available_until = successor.available_until;
    manifest.useful_output_limit = successor.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed_statement = SignedLifecycleTaskV2 {
        lease_id: successor.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    let source_key = signing_key_from_hex(
        &hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])),
    )
    .unwrap();
    signed_statement.signature = hex::decode(sign_hex(
        &source_key,
        &signed_statement.signing_message().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let open_tx = signed(&settings, 2, 1, 18, successor.encode().unwrap());
    let register_tx = signed(&settings, 0, 1, 21, signed_statement.encode().unwrap());
    let include = mine(&mut node, 2, vec![open_tx, register_tx.clone()]);
    assert!(node.lifecycle_task_lease(include, signed_statement.manifest.matrix_task, 3).is_ok());
    assert!(node.lifecycle_task_lease(include, old_task, 3).is_err());
    assert_eq!(
        node.read_active().unwrap().2[continuity_v1::MAINTENANCE_KEY]["useful_output_credit"],
        0,
    );
    for height in 3..=9 {
        mine(&mut node, height, vec![]);
    }
    let confirmation = node.confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000).unwrap();
    assert!(confirmation.confirmed);
    assert!(!confirmation.reorged);
    assert!(!confirmation.finalized);
    assert!(!confirmation.execution_authority);
    let before = node.read_active().unwrap();
    drop(node);
    let reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), before);
    assert!(reopened.confirmation(hash(b"tx-id", &[&register_tx]), include, 100_000)
        .unwrap().confirmed);
}
