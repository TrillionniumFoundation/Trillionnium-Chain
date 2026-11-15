//! Actual packet/state parity for output-meter changes and no-change branches.
use trnm_crypto_primitives::{
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{
    pon_executor::{self, Config},
    qualified_task_lifecycle::{self, slot_key},
};
use trnm_pon_node::{development_public, sequence_root, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::{AtomicRenewTaskV4, ATOMIC_RENEW_TAG, PROFILE},
        TaskPurpose,
    },
};
const POLICY: &str = "native-public-evaluation-dev-v1";
const CLOCK: u64 = 1_800_010_000;
fn signature(who: u64, message: &[u8]) -> [u8; 64] {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    hex::decode(sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn transaction(s: &Settings, who: u64, sequence: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: s.network(),
        sender: development_public(who).unwrap(),
        nonce: sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(who, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
fn statement(
    s: &Settings,
    current: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
    sequence: u64,
) -> SignedLifecycleTaskV2 {
    let mut manifest = s.bootstrap_lifecycle_task().unwrap().signed.manifest;
    let (a, b) = derive_matrices(model, input).unwrap();
    manifest.purpose = current.purpose;
    manifest.source = current.source;
    manifest.demand_id = current.demand_id;
    manifest.source_record = current.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[model]);
    manifest.layer =
        trnm_protocol::qualified_work_task::QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[input]);
    manifest.matrix_task = trnm_crypto_primitives::pon_work::task_id(&a, &b).unwrap();
    manifest.availability_manifest = current.availability_manifest;
    manifest.availability_root = current.availability_root;
    manifest.authorization_scope = current.authorization_scope;
    manifest.withdrawal_head = current.withdrawal_frontier().unwrap();
    manifest.demand_nonce = sequence;
    manifest.not_before = current.not_before;
    manifest.expires = current.expires;
    manifest.available_until = current.available_until;
    manifest.useful_output_limit = current.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: current.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    signed.signature = signature(0, &signed.signing_message().unwrap());
    signed
}
fn make(
    node: &Node,
    parent: Hash,
    transactions: Vec<Vec<u8>>,
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    model: &[u8],
    input: &[u8],
) -> Packet {
    let (a, b) = derive_matrices(model, input).unwrap();
    let height = node.parent_height(parent).unwrap() + 1;
    let admission = verify_lifecycle_admission(
        &signed.encode().unwrap(),
        TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        },
        lease,
        height,
    )
    .unwrap();
    node.make_with_task(
        parent,
        transactions,
        development_public(3).unwrap(),
        1_800_000_000 + height * 10,
        4096,
        &admission,
        TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        },
    )
    .unwrap()
}
fn admit(node: &mut Node, packet: &Packet) -> Hash {
    let id = node.admit(packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}
fn assert_full_recomputation(
    node: &mut Node,
    packet: &Packet,
    model: &[u8],
    input: &[u8],
    expected_change: bool,
) -> Hash {
    let cfg = Config::installed_with_profiles(POLICY, PROFILE).unwrap();
    let before = node.state_at(packet.header.parent).unwrap();
    let eligible = qualified_task_lifecycle::eligible_task(
        &before,
        packet.header.work_task,
        packet.header.height,
        &cfg,
    )
    .unwrap();
    let mut full = pon_executor::execute(
        &before,
        &packet.transactions,
        packet.header.height,
        packet.header.miner,
        packet.header.parent,
        1,
        &cfg,
    )
    .unwrap();
    let (a, b) = derive_matrices(model, input).unwrap();
    let prepared = trnm_crypto_primitives::pon_work::PreparedTask::new(&a, &b).unwrap();
    let changed = qualified_task_lifecycle::consume_output(
        &mut full.state,
        &eligible,
        hash(b"qualified-task-product-v1", &[prepared.product_bytes()]),
        packet.header.height,
    )
    .unwrap();
    assert_eq!(changed, expected_change);
    assert_eq!(
        packet.header.state,
        pon_executor::root(&full.state).unwrap()
    );
    if !changed {
        assert_eq!(packet.header.state, full.root, "reuse this execution root");
    }
    assert_eq!(
        packet.header.receipts,
        sequence_root("receipts", &full.receipts)
    );
    let id = admit(node, packet);
    assert_eq!(node.state_at(id).unwrap(), full.state);
    id
}

fn reprove(packet: &mut Packet, model: &[u8], input: &[u8]) {
    let (a, b) = derive_matrices(model, input).unwrap();
    let prepared = trnm_crypto_primitives::pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        packet.header.nonce = nonce;
        let proof = prepared.prove(packet.header.challenge()).unwrap();
        if hash(
            b"ticket",
            &[&packet.header.challenge(), &proof[proof.len() - 32..]],
        ) <= packet.header.target
        {
            packet.proof = proof;
            return;
        }
    }
    panic!("finite development work budget exhausted");
}

#[test]
fn first_repeated_and_maintenance_atomic_packets_equal_complete_native_recomputation() {
    let temp = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (bm, bi, _, _) = s.bootstrap_task_material().unwrap();
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let mut lease = boot.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.purpose = TaskPurpose::InferenceContraction;
    lease.requester = development_public(2).unwrap();
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    lease.demand_id = lease.derived_demand_id();
    let signed = statement(&s, &lease, &model, &input, 1);
    let mut node = Node::open(temp.path(), s.clone(), 4).unwrap();
    let register = make(
        &node,
        s.genesis(),
        vec![
            transaction(&s, 2, 1, 18, lease.encode().unwrap()),
            transaction(&s, 0, 1, 21, signed.encode().unwrap()),
        ],
        &boot.signed,
        &boot.lease,
        &bm,
        &bi,
    );
    let registered = assert_full_recomputation(&mut node, &register, &bm, &bi, false);
    let first = make(&node, registered, vec![], &signed, &lease, &model, &input);
    let used = assert_full_recomputation(&mut node, &first, &model, &input, true);
    let repeated = make(&node, used, vec![], &signed, &lease, &model, &input);
    let repeated_parent = assert_full_recomputation(&mut node, &repeated, &model, &input, false);
    let cfg = Config::installed_with_profiles(POLICY, PROFILE).unwrap();
    let before = node.state_at(repeated_parent).unwrap();
    let eligible =
        qualified_task_lifecycle::eligible_task(&before, signed.manifest.matrix_task, 4, &cfg)
            .unwrap();
    let product = hash(
        b"qualified-task-product-v1",
        &[trnm_crypto_primitives::pon_work::PreparedTask::new(
            &derive_matrices(&model, &input).unwrap().0,
            &derive_matrices(&model, &input).unwrap().1,
        )
        .unwrap()
        .product_bytes()],
    );
    let mut conflicting = before.clone();
    conflicting.get_mut(&slot_key(1).unwrap()).unwrap()["output_product"] =
        serde_json::json!(hex::encode([99; 32]));
    let unchanged = conflicting.clone();
    assert_eq!(
        qualified_task_lifecycle::consume_output(&mut conflicting, &eligible, product, 4),
        Err("TASK_OUTPUT_CONFLICT")
    );
    assert_eq!(conflicting, unchanged);
    let mut wrong_slot = before.clone();
    let mut mismatched_lease = lease.clone();
    mismatched_lease.generation = 99;
    mismatched_lease.demand_id = mismatched_lease.derived_demand_id();
    wrong_slot.get_mut(&slot_key(1).unwrap()).unwrap()["lease"] =
        serde_json::json!(hex::encode(mismatched_lease.encode().unwrap()));
    let unchanged = wrong_slot.clone();
    assert_eq!(
        qualified_task_lifecycle::consume_output(&mut wrong_slot, &eligible, product, 4),
        Err("TASK_DEMAND")
    );
    assert_eq!(wrong_slot, unchanged);

    let maintenance_eligible =
        qualified_task_lifecycle::eligible_task(&before, boot.signed.manifest.matrix_task, 4, &cfg)
            .unwrap();
    let mut wrong_maintenance_slot = before.clone();
    let mut wrong_maintenance_lease = boot.lease.clone();
    wrong_maintenance_lease.generation = 99;
    wrong_maintenance_lease.demand_id = wrong_maintenance_lease.derived_demand_id();
    wrong_maintenance_slot
        .get_mut(&slot_key(0).unwrap())
        .unwrap()["lease"] =
        serde_json::json!(hex::encode(wrong_maintenance_lease.encode().unwrap()));
    let unchanged = wrong_maintenance_slot.clone();
    assert_eq!(
        qualified_task_lifecycle::consume_output(
            &mut wrong_maintenance_slot,
            &maintenance_eligible,
            product,
            4
        ),
        Err("TASK_DEMAND")
    );
    assert_eq!(wrong_maintenance_slot, unchanged);

    let mut successor = boot.lease.clone();
    successor.revision += 1;
    successor.not_before = 1;
    successor.expires = 1001;
    successor.available_until = 1101;
    let resigned = statement(&s, &successor, &bm, &bi, 2);
    let atomic = make(
        &node,
        repeated_parent,
        vec![transaction(
            &s,
            1,
            1,
            ATOMIC_RENEW_TAG,
            AtomicRenewTaskV4 {
                lease: successor.clone(),
                signed: resigned.clone(),
            }
            .encode()
            .unwrap(),
        )],
        &boot.signed,
        &boot.lease,
        &bm,
        &bi,
    );
    let mut false_root = atomic.clone();
    false_root.header.state[0] ^= 1;
    reprove(&mut false_root, &bm, &bi);
    let stats = node.stats().unwrap();
    assert_eq!(
        node.admit(&false_root, CLOCK).unwrap_err().to_string(),
        "ROOT"
    );
    assert_eq!(node.stats().unwrap(), stats);
    let renewed = assert_full_recomputation(&mut node, &atomic, &bm, &bi, false);
    let current = node.state_at(renewed).unwrap();
    let active_lease = DemandLeaseV2::decode(
        &hex::decode(current[&slot_key(0).unwrap()]["lease"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(active_lease.revision, 2);
    assert_eq!(current[&slot_key(1).unwrap()]["output_count"], 1);
    assert_ne!(
        current, before,
        "maintenance work still applies signed atomic transaction"
    );
    drop(node);
    let mut node = Node::open(temp.path(), s, 1).unwrap();
    assert_eq!(node.read_active().unwrap().2, current);
    let after = make(&node, renewed, vec![], &resigned, &successor, &bm, &bi);
    assert_full_recomputation(&mut node, &after, &bm, &bi, false);
}

#[test]
fn signed_v1_first_and_repeated_packets_equal_complete_native_recomputation() {
    use trnm_crypto_primitives::qualified_work_task::verify_development_admission;
    use trnm_mvcc_fee::pon_executor::SIGNED_TASK_PROFILE;

    let temp = tempfile::tempdir().unwrap();
    let policy = "legacy-first-two-v3";
    let s = Settings::development_with_profiles(None, policy, SIGNED_TASK_PROFILE).unwrap();
    let cfg = Config::installed_with_profiles(policy, SIGNED_TASK_PROFILE).unwrap();
    let bootstrap = s.bootstrap_task_statement().unwrap();
    let (bm, bi, _, _) = s.bootstrap_task_material().unwrap();
    let model: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 11 + 7) % 97).to_le_bytes())
        .collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| ((i * 17 + 5) % 101).to_le_bytes())
        .collect();
    let signed = s
        .development_task_manifest(
            1,
            TaskPurpose::InferenceContraction,
            &model,
            &input,
            1,
            100,
            2,
        )
        .unwrap();
    let mut node = Node::open(temp.path(), s.clone(), 2).unwrap();
    let mut parent = s.genesis();
    let key = format!("work-output:{}", hex::encode(signed.manifest.output_meter));
    for height in 1..=3 {
        let (manifest, model, input) = if height == 1 {
            (&bootstrap, &bm, &bi)
        } else {
            (&signed, &model, &input)
        };
        let (a, b) = derive_matrices(model, input).unwrap();
        let material = TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        };
        let context = s
            .qualified_task_context(manifest.manifest.demand_id, height)
            .unwrap();
        let permit =
            verify_development_admission(&manifest.encode().unwrap(), material, &context).unwrap();
        let raws = if height == 1 {
            vec![transaction(&s, 0, 1, 13, signed.encode().unwrap())]
        } else {
            vec![]
        };
        let packet = node
            .make_with_task(
                parent,
                raws,
                development_public(3).unwrap(),
                s.genesis_time() + height * 10,
                4096,
                &permit,
                TaskMaterial {
                    model,
                    input,
                    a: &a,
                    b: &b,
                },
            )
            .unwrap();
        let before = node.state_at(parent).unwrap();
        let mut expected = pon_executor::execute(
            &before,
            &packet.transactions,
            height,
            packet.header.miner,
            parent,
            1,
            &cfg,
        )
        .unwrap();
        if height > 1 {
            let product = trnm_crypto_primitives::pon_work::PreparedTask::new(&a, &b).unwrap();
            let value = serde_json::json!({
                "product": hex::encode(hash(b"qualified-task-product-v1", &[product.product_bytes()])),
                "arithmetic_output_count": 1,
                "matrix_task": hex::encode(signed.manifest.matrix_task),
                "scope": "source-attested-fixed-contraction-not-model-value"
            });
            if height == 2 {
                assert!(!expected.state.contains_key(&key));
                expected.state.insert(key.clone(), value);
            } else {
                assert_eq!(expected.state[&key], value);
            }
        }
        assert_eq!(
            packet.header.state,
            pon_executor::root(&expected.state).unwrap()
        );
        if height != 2 {
            assert_eq!(packet.header.state, expected.root);
        }
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &expected.receipts)
        );
        parent = admit(&mut node, &packet);
        assert_eq!(node.state_at(parent).unwrap(), expected.state);
    }
}
