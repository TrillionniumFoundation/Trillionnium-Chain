//! Legal signed one-zero/rank-one work remains bound to actual parent authority.
//! All actors use disclosed development keys; no source or hardness qualification.
use trnm_crypto_primitives::{
    pon_work::{self, blocked_one_zero::BlockedOneZeroRankOnePreparedTask},
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, DevelopmentTaskAdmission,
        TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{continuity_v1, qualified_task_lifecycle::slot_key};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::PROFILE,
        QualifiedWorkTask, TaskPurpose,
    },
};

const CLOCK: u64 = 1_800_010_000;
type Material = (Vec<u8>, Vec<u8>, Vec<u32>, Vec<u32>);

fn material(m: &Material) -> TaskMaterial<'_> {
    TaskMaterial {
        model: &m.0,
        input: &m.1,
        a: &m.2,
        b: &m.3,
    }
}
fn signature(actor: u64, message: &[u8]) -> [u8; 64] {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&actor.to_le_bytes()]))).unwrap();
    hex::decode(sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn transaction(s: &Settings, actor: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: s.network(),
        sender: development_public(actor).unwrap(),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(actor, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}
fn statement(
    s: &Settings,
    lease: &DemandLeaseV2,
    m: &Material,
    sequence: u64,
) -> SignedLifecycleTaskV2 {
    let mut manifest = s.bootstrap_lifecycle_task().unwrap().signed.manifest;
    manifest.purpose = lease.purpose;
    manifest.source = lease.source;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease.bound_source_record().unwrap();
    manifest.model = hash(b"artifact", &[&m.0]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&m.1]);
    manifest.matrix_task = pon_work::task_id(&m.2, &m.3).unwrap();
    manifest.availability_manifest = lease.availability_manifest;
    manifest.availability_root = lease.availability_root;
    manifest.authorization_scope = lease.authorization_scope;
    manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    manifest.demand_nonce = sequence;
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
    signed.signature = signature(0, &signed.signing_message().unwrap());
    signed
}
fn permit(
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    m: &Material,
    height: u64,
) -> DevelopmentTaskAdmission {
    verify_lifecycle_admission(&signed.encode().unwrap(), material(m), lease, height).unwrap()
}
fn make(
    node: &Node,
    parent: Hash,
    transactions: Vec<Vec<u8>>,
    permit: &DevelopmentTaskAdmission,
    m: &Material,
) -> trnm_pon_node::Result<Packet> {
    let height = node.parent_height(parent).unwrap() + 1;
    node.make_with_task(
        parent,
        transactions,
        development_public(3).unwrap(),
        node.settings().genesis_time() + height * 10,
        4096,
        permit,
        material(m),
    )
}
fn activate(node: &mut Node, packet: &Packet) -> Hash {
    let id = node.admit(packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    id
}
fn reject(
    node: &Node,
    parent: Hash,
    permit: &DevelopmentTaskAdmission,
    m: &Material,
    expected: &str,
) {
    let before = node.read_active().unwrap();
    for _ in 0..2 {
        assert_eq!(
            make(node, parent, vec![], permit, m)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
    assert_eq!(node.read_active().unwrap(), before);
}
#[test]
fn signed_one_zero_rank_one_work_uses_actual_parent_authority_in_both_directions() {
    for profile in [PROFILE, continuity_v1::PROFILE] {
        for zero_on_left in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let s = Settings::development_with_profiles(
                None,
                "native-public-evaluation-dev-v1",
                profile,
            )
            .unwrap();
            let boot = s.bootstrap_lifecycle_task().unwrap();
            let base = s.bootstrap_task_material().unwrap();
            let other: Vec<u32> = (0..pon_work::CELLS)
                .map(|position| {
                    ((position / pon_work::N + 1) * (position % pon_work::N + 3)) as u32
                })
                .collect();
            let other_bytes: Vec<u8> = other.iter().flat_map(|value| value.to_le_bytes()).collect();
            let zero_bytes = vec![0; pon_work::CELLS * 4];
            let (model, input) = if zero_on_left {
                (zero_bytes, other_bytes)
            } else {
                (other_bytes, zero_bytes)
            };
            let (a, b) = derive_matrices(&model, &input).unwrap();
            let task_material = (model, input, a, b);
            assert_eq!(
                task_material.2.iter().all(|value| *value == 0),
                zero_on_left
            );
            assert_eq!(
                task_material.3.iter().all(|value| *value == 0),
                !zero_on_left
            );
            // Complete mathematical preparation predates signed registration.
            let cached = BlockedOneZeroRankOnePreparedTask::new(&task_material.2, &task_material.3)
                .unwrap()
                .unwrap();
            let mut lease = boot.lease.clone();
            lease.slot = 1;
            lease.generation = 2;
            lease.requester = development_public(2).unwrap();
            lease.purpose = TaskPurpose::Maintenance;
            lease.not_before = 1;
            lease.expires = 4;
            lease.available_until = 104;
            lease.demand_id = lease.derived_demand_id();
            let signed = statement(&s, &lease, &task_material, 1);
            let checked = permit(&signed, &lease, &task_material, 2);
            let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
            reject(&node, s.genesis(), &checked, &task_material, "TASK");
            let registration = make(
                &node,
                s.genesis(),
                vec![
                    transaction(&s, 2, 1, 18, lease.encode().unwrap()),
                    transaction(&s, 0, 1, 21, signed.encode().unwrap()),
                ],
                &permit(&boot.signed, &boot.lease, &base, 1),
                &base,
            )
            .unwrap();
            let registered = activate(&mut node, &registration);
            let mut candidate = make(&node, registered, vec![], &checked, &task_material).unwrap();
            let challenge = candidate.header.challenge();
            let blocked = cached.prove(challenge).unwrap();
            assert_eq!(blocked, candidate.proof);
            assert_eq!(
                blocked,
                pon_work::prove(challenge, &task_material.2, &task_material.3).unwrap()
            );
            let ordinary = pon_work::verify(
                challenge,
                signed.manifest.matrix_task,
                candidate.header.target,
                &blocked,
            )
            .unwrap();
            let scalar = pon_work::verify_reference(
                challenge,
                signed.manifest.matrix_task,
                candidate.header.target,
                &blocked,
            )
            .unwrap();
            assert_eq!(ordinary.ticket(), scalar.ticket());
            assert!(ordinary.product().iter().all(|value| *value == 0));
            candidate.proof = blocked;
            let used = activate(&mut node, &candidate);
            let before = node.read_active().unwrap();
            assert_eq!(before.0, used);
            assert_eq!(before.2[&slot_key(1).unwrap()]["output_count"], 0);
            let mut changed = task_material.clone();
            // A valid mathematical cache cannot excuse changed signed source bytes.
            changed.0[0] ^= 1;
            reject(&node, used, &checked, &changed, "TASK_MATERIAL");
            assert_eq!(node.read_active().unwrap(), before);
            drop(node);
            let mut reopened = Node::open(dir.path(), s, 1).unwrap();
            assert_eq!(reopened.read_active().unwrap(), before);
            let mut next = make(&reopened, used, vec![], &checked, &task_material).unwrap();
            assert_eq!(cached.prove(next.header.challenge()).unwrap(), next.proof);
            next.proof = cached.prove(next.header.challenge()).unwrap();
            let final_id = activate(&mut reopened, &next);
            assert_eq!(reopened.read_active().unwrap().0, final_id);
            assert_eq!(
                reopened.state_at(final_id).unwrap()[&slot_key(1).unwrap()]["output_count"],
                0
            );
        }
    }
}
