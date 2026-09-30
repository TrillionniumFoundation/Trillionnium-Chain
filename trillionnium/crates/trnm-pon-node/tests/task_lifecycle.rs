//! Actual v2 packets use parent leases, re-sign after renewal and stop on revoke.
use serde_json::Value;
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
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2, PROFILE},
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
fn renew_keeps_one_output_revoke_stops_new_work_and_reopen_reorg_are_real() {
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
        vec![
            transaction(&s, 2, 2, 19, successor.encode().unwrap()),
            transaction(&s, 0, 2, 21, resigned.encode().unwrap()),
        ],
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
#[test]
fn v2_genesis_and_statement_never_reinterpret_v1_store() {
    let temp = tempfile::tempdir().unwrap();
    let v1 = Settings::development_with_profiles(None, POLICY, "signed-task-dev-v1").unwrap();
    let v2 = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    assert_ne!(v1.genesis(), v2.genesis());
    assert_ne!(v1.parameters(), v2.parameters());
    let node = Node::open(temp.path(), v1.clone(), 1).unwrap();
    drop(node);
    assert!(Node::open(temp.path(), v2, 1).is_err());
    let wire = v1.bootstrap_task_statement().unwrap().encode().unwrap();
    assert!(SignedLifecycleTaskV2::decode(&wire).is_err());
    let state: Value =
        serde_json::json!({"test_scope":"no production liveness or hard-work bound inferred"});
    assert!(state.is_object());
}
#[test]
fn real_model_family_uses_a_distinct_namespace_and_enforces_its_artifact_budget() {
    use trnm_mvcc_fee::pon_executor::Config;
    assert!(Settings::development_with_model_profiles(
        None,
        "closed-round-all-eligible-min-v1",
        PROFILE,
        "smollm2-135m-cpu-dev-v1"
    )
    .is_err());
    let old = Settings::development_with_profiles(None, POLICY, PROFILE).unwrap();
    let settings =
        Settings::development_with_model_profiles(None, POLICY, PROFILE, "smollm2-135m-cpu-dev-v1")
            .unwrap();
    assert_ne!(old.genesis(), settings.genesis());
    assert_ne!(old.parameters(), settings.parameters());
    let dir = tempfile::tempdir().unwrap();
    let old_node = Node::open(dir.path(), old, 1).unwrap();
    drop(old_node);
    assert!(Node::open(dir.path(), settings.clone(), 1).is_err());
    let fresh = tempfile::tempdir().unwrap();
    let node = Node::open(fresh.path(), settings.clone(), 1).unwrap();
    let before = node.stats().unwrap();
    let cfg =
        Config::installed_with_model_profiles(POLICY, PROFILE, "smollm2-135m-cpu-dev-v1").unwrap();
    let artifact = [3; 32];
    let components = [7; 32];
    let cid = hash(
        b"contribution-v3",
        &[
            &development_public(3).unwrap(),
            &cfg.family,
            &[0; 32],
            &artifact,
            &components,
            &0_u64.to_le_bytes(),
        ],
    );
    let mut payload = Vec::new();
    for h in [cid, cfg.family, [0; 32], artifact] {
        payload.extend(h);
    }
    payload.extend(2_097_153_u64.to_le_bytes());
    payload.extend(components);
    payload.extend(0_u64.to_le_bytes());
    let tx = transaction(&settings, 3, 1, 6, payload);
    let bootstrap = settings.bootstrap_lifecycle_task().unwrap();
    let (model, input, a, b) = settings.bootstrap_task_material().unwrap();
    let admission = verify_lifecycle_admission(
        &bootstrap.signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &bootstrap.lease,
        1,
    )
    .unwrap();
    let result = node.make_with_task(
        settings.genesis(),
        vec![tx],
        development_public(0).unwrap(),
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
    assert_eq!(result.unwrap_err().to_string(), "LIMIT");
    assert_eq!(node.stats().unwrap(), before);
}
