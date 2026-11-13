//! P0-A: Rev12 may carry a freshly authorized task without any live external
//! lease. The test constructs real signed PNX1, W1, native branch state,
//! independently checked receipt and cold recovery; it is not public WAN proof.
use trnm_crypto_primitives::{
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2},
        TaskPurpose,
    },
};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn transaction(settings: &Settings, owner: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(owner),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&owner.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn signed_new_task(
    settings: &Settings,
    lease: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
) -> SignedLifecycleTaskV2 {
    let mut manifest = settings.bootstrap_lifecycle_task().unwrap().signed.manifest;
    let (a, b) = derive_matrices(model, input).unwrap();
    manifest.purpose = lease.purpose;
    manifest.source = lease.source;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[model]);
    manifest.layer =
        trnm_protocol::qualified_work_task::QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[input]);
    manifest.matrix_task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    manifest.availability_manifest = lease.availability_manifest;
    manifest.availability_root = lease.availability_root;
    manifest.authorization_scope = lease.authorization_scope;
    manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    manifest.demand_nonce = 1;
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.useful_output_limit = lease.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    signed.signature = hex::decode(sign_hex(&key, &signed.signing_message().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    signed
}

#[test]
fn all_external_leases_revoked_maintenance_registers_new_signed_task_and_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let reference_path = dir.path().join("reference");
    let replica_path = dir.path().join("replica");
    let mut producer = Node::open(&reference_path, settings.clone(), 1).unwrap();
    let mut replica =
        Node::open_with_authenticated_state(&replica_path, settings.clone(), 2).unwrap();
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let revoked_task = bootstrap.signed.manifest.matrix_task;
    let revoke = DemandRevocationV2 {
        network: settings.network(),
        parameters: settings.parameters(),
        slot: 0,
        demand_id: bootstrap.lease.demand_id,
        requester: bootstrap.lease.requester,
        expected_revision: bootstrap.lease.revision,
    };
    let revoked_tx = transaction(&settings, 1, 1, 20, revoke.encode().unwrap());
    let mut tip = settings.genesis();
    let first = producer
        .make_consensus_maintenance(tip, vec![revoked_tx], public(0), 11, 4096)
        .unwrap();
    tip = first.id().unwrap();
    assert_eq!(producer.admit(&first, 100_000).unwrap(), tip);
    assert_eq!(replica.admit(&first, 100_000).unwrap(), tip);
    producer.activate(tip).unwrap();
    replica.activate(tip).unwrap();
    assert!(producer.lifecycle_task_lease(tip, revoked_task, 2).is_err());

    // Open and register a DIFFERENT source-signed task in a Maintenance block.
    // There is no live requester/source lease for the current work.
    let mut lease = bootstrap.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.requester = public(2);
    lease.not_before = 2;
    lease.expires = 1002;
    lease.available_until = 1102;
    lease.demand_id = lease.derived_demand_id();
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let signed = signed_new_task(&settings, &lease, &model, &input);
    let open = transaction(&settings, 2, 1, 18, lease.encode().unwrap());
    let register = transaction(&settings, 0, 1, 21, signed.encode().unwrap());
    let register_id = hash(b"tx-id", &[&register]);
    let packet = producer
        .make_consensus_maintenance(tip, vec![open, register], public(0), 21, 4096)
        .unwrap();
    tip = packet.id().unwrap();
    assert_eq!(producer.admit(&packet, 100_000).unwrap(), tip);
    assert_eq!(replica.admit(&packet, 100_000).unwrap(), tip);
    producer.activate(tip).unwrap();
    replica.activate(tip).unwrap();
    let included = tip;
    assert_eq!(
        producer
            .lifecycle_task_lease(tip, signed.manifest.matrix_task, 3)
            .unwrap()
            .id()
            .unwrap(),
        lease.id().unwrap()
    );

    // Actual later W1 uses the independently signed external task.
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let admission = verify_lifecycle_admission(
        &signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &lease,
        3,
    )
    .unwrap();
    let resumed = producer
        .make_with_task(
            tip,
            vec![],
            public(3),
            31,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
        )
        .unwrap();
    tip = resumed.id().unwrap();
    assert_eq!(producer.admit(&resumed, 100_000).unwrap(), tip);
    assert_eq!(replica.admit(&resumed, 100_000).unwrap(), tip);
    producer.activate(tip).unwrap();
    replica.activate(tip).unwrap();

    // Six additional complete maintenance blocks yield policy confirmation.
    for height in 4..=10 {
        let packet = producer
            .make_consensus_maintenance(tip, vec![], public(0), 1 + height * 10, 4096)
            .unwrap();
        tip = packet.id().unwrap();
        assert_eq!(producer.admit(&packet, 100_000).unwrap(), tip);
        assert_eq!(replica.admit(&packet, 100_000).unwrap(), tip);
        producer.activate(tip).unwrap();
        replica.activate(tip).unwrap();
        assert_eq!(
            producer.read_active().unwrap(),
            replica.read_active().unwrap()
        );
    }
    let receipt = replica
        .confirmation(register_id, included, 100_000)
        .unwrap();
    assert!(receipt.confirmed);
    assert!(!receipt.reorged);
    assert!(!receipt.finalized);
    assert!(!receipt.execution_authority);
    assert_eq!(
        producer.read_active().unwrap(),
        replica.read_active().unwrap()
    );
    let before = replica.read_active().unwrap();
    drop(replica);
    replica = Node::open_with_authenticated_state(&replica_path, settings, 1).unwrap();
    assert_eq!(replica.read_active().unwrap(), before);
    assert!(
        replica
            .confirmation(register_id, included, 100_000)
            .unwrap()
            .confirmed
    );
    eprintln!("continuity research: revoked=true, maintenance_block=true, new_signed_task=true, real_W1=true, client_confirmation=true, independent_operators=false, work_hardness=false");
}
