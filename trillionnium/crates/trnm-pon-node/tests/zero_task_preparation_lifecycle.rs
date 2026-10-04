//! Legal signed zero material remains separate from reusable mathematical preparation.
//! All actors use disclosed development keys; no source or hardness qualification.
use trnm_crypto_primitives::{
    pon_work::{self, blocked_zero::BlockedZeroPreparedTask},
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, AdmissionError,
        DevelopmentTaskAdmission, TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{continuity_v1, qualified_task_lifecycle::slot_key};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2},
        lifecycle_v4::{AtomicRenewTaskV4, ATOMIC_RENEW_TAG, PROFILE},
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
fn explicit_maintenance(
    node: &mut Node,
    parent: Hash,
    zero_task: Hash,
    continuity: bool,
) -> Option<Hash> {
    let height = node.parent_height(parent).unwrap() + 1;
    let result = node.make_consensus_maintenance(
        parent,
        vec![],
        development_public(3).unwrap(),
        node.settings().genesis_time() + height * 10,
        4096,
    );
    if continuity {
        let packet = result.unwrap();
        assert_ne!(packet.header.work_task, zero_task);
        pon_work::verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
        let admitted = node.admit(&packet, CLOCK).unwrap();
        assert_eq!(admitted, packet.id().unwrap());
        Some(admitted)
    } else {
        assert_eq!(result.unwrap_err().to_string(), "CONTINUITY_PROFILE");
        None
    }
}

#[test]
fn signed_zero_preparation_never_replaces_parent_renewal_revocation_or_expiry() {
    for profile in [PROFILE, continuity_v1::PROFILE] {
        let dir = tempfile::tempdir().unwrap();
        let s =
            Settings::development_with_profiles(None, "native-public-evaluation-dev-v1", profile)
                .unwrap();
        let boot = s.bootstrap_lifecycle_task().unwrap();
        let base = s.bootstrap_task_material().unwrap();
        let bytes = vec![0; pon_work::CELLS * 4];
        let (a, b) = derive_matrices(&bytes, &bytes).unwrap();
        let zero = (bytes.clone(), bytes, a, b);
        // This object predates registration and carries only a mathematical cache.
        let cached = BlockedZeroPreparedTask::new(&zero.2, &zero.3)
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
        let signed = statement(&s, &lease, &zero, 1);
        let old_permit = permit(&signed, &lease, &zero, 2);
        let zero_task = signed.manifest.matrix_task;
        let mut node = Node::open(dir.path(), s.clone(), 1).unwrap();
        reject(&node, s.genesis(), &old_permit, &zero, "TASK");
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
        let mut use_zero = make(&node, registered, vec![], &old_permit, &zero).unwrap();
        let challenge = use_zero.header.challenge();
        let blocked = cached.prove(challenge).unwrap();
        assert_eq!(blocked, use_zero.proof);
        assert_eq!(
            blocked,
            pon_work::prove(challenge, &zero.2, &zero.3).unwrap()
        );
        use_zero.proof = blocked;
        let used = activate(&mut node, &use_zero);
        assert_eq!(
            node.state_at(used).unwrap()[&slot_key(1).unwrap()]["output_count"],
            0
        );

        let mut successor = lease.clone();
        successor.revision = 2;
        successor.not_before = 3;
        successor.expires = 6;
        successor.available_until = 106;
        let renewed_statement = statement(&s, &successor, &zero, 2);
        assert_eq!(renewed_statement.manifest.matrix_task, zero_task);
        assert_eq!(
            renewed_statement.manifest.output_meter,
            signed.manifest.output_meter
        );
        let renewal = make(
            &node,
            used,
            vec![transaction(
                &s,
                2,
                2,
                ATOMIC_RENEW_TAG,
                AtomicRenewTaskV4 {
                    lease: successor.clone(),
                    signed: renewed_statement.clone(),
                }
                .encode()
                .unwrap(),
            )],
            &old_permit,
            &zero,
        )
        .unwrap();
        let renewed = activate(&mut node, &renewal);
        reject(&node, renewed, &old_permit, &zero, "TASK_ADMISSION_CONTEXT");
        let new_permit = permit(&renewed_statement, &successor, &zero, 4);
        let mut changed = zero.clone();
        changed.0[0] = 1;
        reject(&node, renewed, &new_permit, &changed, "TASK_MATERIAL");
        let fourth = make(&node, renewed, vec![], &new_permit, &zero).unwrap();
        assert_eq!(
            cached.prove(fourth.header.challenge()).unwrap(),
            fourth.proof
        );
        let live = activate(&mut node, &fourth);
        assert_eq!(
            node.state_at(live).unwrap()[&slot_key(1).unwrap()]["output_count"],
            0
        );

        let revocation = DemandRevocationV2 {
            slot: 1,
            network: s.network(),
            parameters: s.parameters(),
            demand_id: lease.demand_id,
            requester: lease.requester,
            expected_revision: 2,
        };
        let fifth = make(
            &node,
            live,
            vec![transaction(&s, 2, 3, 20, revocation.encode().unwrap())],
            &new_permit,
            &zero,
        )
        .unwrap();
        let revoked = activate(&mut node, &fifth);
        reject(&node, revoked, &new_permit, &zero, "TASK");
        // A complete valid relation still exists after revocation. It conveys no
        // lease or branch-state authority and cannot authorize another candidate.
        let proof = cached.prove([7; 32]).unwrap();
        pon_work::verify([7; 32], zero_task, [255; 32], &proof).unwrap();
        permit(&renewed_statement, &successor, &zero, 6);
        explicit_maintenance(
            &mut node,
            revoked,
            zero_task,
            profile == continuity_v1::PROFILE,
        );

        let mut fork = live;
        for _ in 5..=6 {
            let packet = make(&node, fork, vec![], &new_permit, &zero).unwrap();
            assert_eq!(
                cached.prove(packet.header.challenge()).unwrap(),
                packet.proof
            );
            fork = node.admit(&packet, CLOCK).unwrap();
        }
        reject(&node, fork, &new_permit, &zero, "TASK");
        assert!(matches!(
            verify_lifecycle_admission(
                &renewed_statement.encode().unwrap(),
                material(&zero),
                &successor,
                7
            ),
            Err(AdmissionError::Height)
        ));
        let recovered_tip = explicit_maintenance(
            &mut node,
            fork,
            zero_task,
            profile == continuity_v1::PROFILE,
        )
        .unwrap_or(fork);
        let active = node.read_active().unwrap();
        assert_eq!(active.0, revoked);
        assert_eq!(active.2[&slot_key(1).unwrap()]["status"], "revoked");
        assert_eq!(active.2[&slot_key(1).unwrap()]["output_count"], 0);
        let expired_branch = node.state_at(fork).unwrap();
        drop(node);
        let reopened = Node::open(dir.path(), s, 1).unwrap();
        // Cold recovery selects the heavier durable branch. Mathematical cache
        // reuse must not alter either branch's previously checked lease state.
        assert_eq!(reopened.read_active().unwrap().0, recovered_tip);
        assert_eq!(reopened.state_at(revoked).unwrap(), active.2);
        assert_eq!(reopened.state_at(fork).unwrap(), expired_branch);
        reject(&reopened, revoked, &new_permit, &zero, "TASK");
        reject(&reopened, fork, &new_permit, &zero, "TASK");
    }
}
