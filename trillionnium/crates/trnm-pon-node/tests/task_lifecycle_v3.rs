//! Fresh V3 packets cannot separate renewal from source authentication.
use trnm_crypto_primitives::{
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::qualified_task_lifecycle::slot_key;
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2},
        lifecycle_v3::{AtomicRenewTaskV3, ATOMIC_RENEW_TAG, PROFILE},
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
#[test]
fn sole_task_atomic_renew_rejects_partial_legacy_bad_signature_window_sequence_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let s = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let boot = s.bootstrap_lifecycle_task().unwrap();
    let (model, input, a, b) = s.bootstrap_task_material().unwrap();
    let mut node = Node::open(dir.path(), s.clone(), 4).unwrap();
    let genesis = s.genesis();
    let before = node.read_active().unwrap();
    let stats = node.stats().unwrap();
    let mut next = boot.lease.clone();
    next.revision = 2;
    next.not_before = 1;
    next.expires = 1001;
    next.available_until = 1101;
    let signed = statement(&s, &next, &model, &input, 2);
    let atomic = AtomicRenewTaskV3 {
        lease: next.clone(),
        signed: signed.clone(),
    };
    let payload = atomic.encode().unwrap();
    assert_eq!(payload.len(), 1028);
    let raw = transaction(&s, 1, 1, ATOMIC_RENEW_TAG, payload.clone());
    assert_eq!(raw.len(), 1187);
    assert_eq!(AtomicRenewTaskV3::decode(&payload).unwrap(), atomic);
    for size in [344, 1027, 1029] {
        let mut malformed = payload.clone();
        malformed.resize(size, 0);
        assert!(AtomicRenewTaskV3::decode(&malformed).is_err());
    }
    let mut invalid = Vec::new();
    let mut partial = raw.clone();
    partial.remove(123);
    invalid.push(("partial", partial));
    invalid.push((
        "standalone19",
        transaction(&s, 1, 1, 19, next.encode().unwrap()),
    ));
    let mut bad = atomic.clone();
    bad.signed.signature[0] ^= 1;
    invalid.push((
        "source_signature",
        transaction(&s, 1, 1, 22, bad.encode().unwrap()),
    ));
    let mut bad = atomic.clone();
    bad.signed = statement(&s, &next, &model, &input, 3);
    invalid.push((
        "source_sequence",
        transaction(&s, 1, 1, 22, bad.encode().unwrap()),
    ));
    let mut badlease = next.clone();
    badlease.expires = 1000;
    badlease.available_until = 1100;
    let bad = AtomicRenewTaskV3 {
        signed: statement(&s, &badlease, &model, &input, 2),
        lease: badlease,
    };
    invalid.push(("window", transaction(&s, 1, 1, 22, bad.encode().unwrap())));
    let mut bad = raw.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    invalid.push(("requester_signature", bad));
    let mut mismatch = payload.clone();
    mismatch[344 + 4] ^= 1;
    assert!(AtomicRenewTaskV3::decode(&mismatch).is_err());
    invalid.push(("unbound_source", transaction(&s, 1, 1, 22, mismatch)));
    let admission = verify_lifecycle_admission(
        &boot.signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &boot.lease,
        1,
    )
    .unwrap();
    for (case, raw) in invalid {
        let result = node.make_with_task(
            genesis,
            vec![raw],
            development_public(3).unwrap(),
            1_800_000_010,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
        );
        assert!(result.is_err(), "{case}");
        assert_eq!(node.read_active().unwrap(), before, "{case}");
        assert_eq!(node.stats().unwrap(), stats, "{case}");
        assert_eq!(
            node.next_nonce(development_public(1).unwrap()).unwrap(),
            1,
            "{case}"
        );
    }
    let packet = make(
        &node,
        genesis,
        vec![raw],
        &boot.signed,
        &boot.lease,
        &model,
        &input,
    );
    let renewed = admit(&mut node, &packet);
    let record = node.read_active().unwrap().2[&slot_key(0).unwrap()].clone();
    assert_eq!(record["source_sequence"], 2);
    assert_eq!(record["output_count"], 0);
    assert_eq!(node.next_nonce(development_public(1).unwrap()).unwrap(), 2);
    // Inner source signature advances per-demand sequence, not source account nonce.
    assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), 1);
    assert_eq!(
        DemandLeaseV2::decode(&hex::decode(record["lease"].as_str().unwrap()).unwrap()).unwrap(),
        next
    );
    assert!(node
        .make_with_task(
            renewed,
            vec![],
            development_public(3).unwrap(),
            1_800_000_020,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b
            }
        )
        .is_err());
    drop(node);
    let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
    assert_eq!(node.read_active().unwrap().2[&slot_key(0).unwrap()], record);
    let tip = make(&node, renewed, vec![], &signed, &next, &model, &input);
    let renewedtip = admit(&mut node, &tip);
    let mut fork = genesis;
    // A heavier branch restoring the original state then atomically renewing at2.
    let one = make(
        &node,
        fork,
        vec![],
        &boot.signed,
        &boot.lease,
        &model,
        &input,
    );
    fork = node.admit(&one, CLOCK).unwrap();
    let mut forklease = next.clone();
    forklease.not_before = 2;
    forklease.expires = 1002;
    forklease.available_until = 1102;
    let forksigned = statement(&s, &forklease, &model, &input, 2);
    let renew = AtomicRenewTaskV3 {
        lease: forklease.clone(),
        signed: forksigned.clone(),
    };
    let two = make(
        &node,
        fork,
        vec![transaction(&s, 1, 1, 22, renew.encode().unwrap())],
        &boot.signed,
        &boot.lease,
        &model,
        &input,
    );
    fork = node.admit(&two, CLOCK).unwrap();
    for _ in 3..=4 {
        let packet = make(&node, fork, vec![], &forksigned, &forklease, &model, &input);
        fork = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    assert_ne!(fork, renewedtip);
    assert_eq!(
        node.lifecycle_task_lease(fork, forksigned.manifest.matrix_task, 5)
            .unwrap(),
        forklease
    );
    let restored = node.read_active().unwrap();
    drop(node);
    assert_eq!(
        Node::open(dir.path(), s, 2).unwrap().read_active().unwrap(),
        restored
    );
}

#[test]
fn v3_never_reinterprets_v2_genesis_store_network_or_tag22_authority() {
    let v2 =
        Settings::development_with_profiles(None, POLICY, "signed-task-lifecycle-dev-v2").unwrap();
    let v3 = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    assert_ne!(v2.network(), v3.network());
    assert_ne!(v2.parameters(), v3.parameters());
    assert_ne!(v2.genesis(), v3.genesis());
    let temp = tempfile::tempdir().unwrap();
    drop(Node::open(temp.path(), v2.clone(), 1).unwrap());
    assert!(Node::open(temp.path(), v3.clone(), 1).is_err());
    let boot = v2.bootstrap_lifecycle_task().unwrap();
    let (model, input, a, b) = v2.bootstrap_task_material().unwrap();
    let mut lease = boot.lease.clone();
    lease.revision = 2;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    let signed = statement(&v2, &lease, &model, &input, 2);
    let raw = transaction(
        &v2,
        1,
        1,
        22,
        AtomicRenewTaskV3 { lease, signed }.encode().unwrap(),
    );
    let node = Node::open(temp.path(), v2.clone(), 1).unwrap();
    let admission = verify_lifecycle_admission(
        &boot.signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &boot.lease,
        1,
    )
    .unwrap();
    let error = node
        .make_with_task(
            v2.genesis(),
            vec![raw],
            development_public(3).unwrap(),
            1_800_000_010,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "WORK_TASK_PROFILE");
}
#[test]
fn atomic_renew_preserves_used_output_meter_and_revoke_reorg_state() {
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
    let genesis = s.genesis();
    let txs = vec![
        transaction(&s, 2, 1, 18, lease.encode().unwrap()),
        transaction(&s, 0, 1, 21, signed.encode().unwrap()),
    ];
    let registration = make(&node, genesis, txs, &boot.signed, &boot.lease, &bm, &bi);
    let base = admit(&mut node, &registration);
    let use_first = make(&node, base, vec![], &signed, &lease, &model, &input);
    let used = admit(&mut node, &use_first);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["output_count"],
        1
    );
    let mut successor = lease.clone();
    successor.revision += 1;
    successor.not_before = 3;
    successor.expires = 1003;
    successor.available_until = 1103;
    let resigned = statement(&s, &successor, &model, &input, 2);
    assert_eq!(resigned.manifest.output_meter, signed.manifest.output_meter);
    let renew = make(
        &node,
        used,
        vec![transaction(
            &s,
            2,
            2,
            ATOMIC_RENEW_TAG,
            AtomicRenewTaskV3 {
                lease: successor.clone(),
                signed: resigned.clone(),
            }
            .encode()
            .unwrap(),
        )],
        &signed,
        &lease,
        &model,
        &input,
    );
    let renewed = admit(&mut node, &renew);
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let old = verify_lifecycle_admission(
        &signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &lease,
        4,
    )
    .unwrap();
    assert!(node
        .make_with_task(
            renewed,
            vec![],
            development_public(3).unwrap(),
            1_800_000_040,
            4096,
            &old,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b
            }
        )
        .is_err());
    drop(node);
    let mut node = Node::open(temp.path(), s.clone(), 1).unwrap();
    let use_again = make(
        &node,
        renewed,
        vec![],
        &resigned,
        &successor,
        &model,
        &input,
    );
    let live = admit(&mut node, &use_again);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["output_count"],
        1
    );
    let revocation = DemandRevocationV2 {
        slot: 1,
        network: s.network(),
        parameters: s.parameters(),
        demand_id: lease.demand_id,
        requester: lease.requester,
        expected_revision: 2,
    };
    let revoked_packet = make(
        &node,
        live,
        vec![transaction(&s, 2, 3, 20, revocation.encode().unwrap())],
        &resigned,
        &successor,
        &model,
        &input,
    );
    let revoked = admit(&mut node, &revoked_packet);
    assert_eq!(
        node.read_active().unwrap().2[&slot_key(1).unwrap()]["status"],
        "revoked"
    );
    assert!(node
        .lifecycle_task_lease(revoked, resigned.manifest.matrix_task, 6)
        .is_err());
    let mut fork = live;
    for _ in 5..=7 {
        let packet = make(&node, fork, vec![], &resigned, &successor, &model, &input);
        fork = node.admit(&packet, CLOCK).unwrap();
    }
    node.activate(fork).unwrap();
    let value = node.read_active().unwrap().2[&slot_key(1).unwrap()].clone();
    assert_eq!(value["status"], "active");
    assert_eq!(value["output_count"], 1);
    drop(node);
    assert_eq!(
        Node::open(temp.path(), s, 2)
            .unwrap()
            .read_active()
            .unwrap()
            .2[&slot_key(1).unwrap()],
        value
    );
}
