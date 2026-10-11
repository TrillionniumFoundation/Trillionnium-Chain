//! Source-only mechanism tests, not an authorized positive Native packet fixture.
use super::*;
use crate::operator_task_policy::{self as policy, tests as fixtures};
use crate::PoolLimits;

#[test]
fn required_mode_file_refuses_both_legacy_openers() {
    let dir = fixtures::directory();
    let marker = dir.path().join("owner-task-policy.required");
    fs::write(&marker, b"retained-required-mode").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    assert_eq!(
        Node::open(dir.path(), settings.clone(), 1)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_POLICY_REQUIRED"
    );
    assert_eq!(
        Node::open_with_fault(dir.path(), settings, 1, None)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_POLICY_REQUIRED"
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn durable_database_mode_refuses_legacy_open_even_without_marker_file() {
    let dir = fixtures::directory();
    let settings = Settings::development(Some(1)).unwrap();
    let node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    node.db
        .execute(
            "INSERT INTO metadata VALUES('operator_task_policy',?)",
            [b"retained-mode".as_slice()],
        )
        .unwrap();
    drop(node);
    assert!(!dir.path().join("owner-task-policy.required").exists());
    assert_eq!(
        Node::open(dir.path(), settings.clone(), 1)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_POLICY_REQUIRED"
    );
    assert_eq!(
        Node::open_with_fault(dir.path(), settings, 1, None)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_POLICY_REQUIRED"
    );
}

#[test]
fn exact_packet_gate_precedes_context_and_pool_hold_changes_no_active_or_pool_rows() {
    let dir = fixtures::directory();
    let journal_dir = fixtures::directory();
    let mut node = Node::open(dir.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    let policy = fixtures::authenticated(fixtures::body());
    let marker = policy.marker(journal_dir.path()).unwrap();
    let journal = policy::Journal::open(journal_dir.path(), fixtures::uid(), &policy).unwrap();
    // Private unit-test assembly only. The production opener still requires
    // external signatures, all six materials, and the durable namespace mode.
    node.owner_policy = Some(OwnerPolicy {
        pool_policies: Vec::new(),
        epoch: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        outside_keys: (String::new(), String::new()),
        policy: std::sync::Arc::new(policy),
        required_marker: marker,
        journal: RefCell::new(journal),
        unavailable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    let active = node.active().unwrap();
    let count = |node: &Node| {
        node.db
            .query_row("SELECT COUNT(*) FROM local_pool_groups", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap()
    };
    let pool_before = count(&node);
    let packet = Packet {
        header: trnm_protocol::pon_wire::Header {
            network: [0; 32],
            parameters: [0; 32],
            parent: [0; 32],
            height: 1,
            timestamp: 11,
            target: [0; 32],
            miner: [0; 32],
            transactions: [0; 32],
            state: [0; 32],
            receipts: [0; 32],
            work_task: [0; 32],
            nonce: 1,
        },
        transactions: Vec::new(),
        proof: vec![0; pon_work::PROOF_BYTES],
    };
    // NETWORK/parent/full-State checks would fail if reached; exact digest
    // refusal must happen first and cannot create a reservation.
    assert_eq!(
        node.check_admission_context(&packet, 11)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_POLICY:NativeBinding"
    );
    assert_eq!(
        node.admit(&packet, 11).err().unwrap().to_string(),
        "OWNER_TASK_POLICY:NativeBinding"
    );
    assert_eq!(
        node.pool_submit_bundle(Vec::new())
            .err()
            .unwrap()
            .to_string(),
        "OWNER_POOL_EXACT_COMMAND_REQUIRED"
    );
    assert_eq!(
        node.pool_reconcile().err().unwrap().to_string(),
        "OWNER_POOL_EXACT_COMMAND_REQUIRED"
    );
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(count(&node), pool_before);
    assert!(!fs::read_dir(journal_dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("claim-")));
}

// Real signed PNX and whole M06 prefix tests. The private unit assembly deliberately
// skips the external six-material opener and is not a positive operator qualification.
fn pool_transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    let mut payload = crate::development_public(1).unwrap().to_vec();
    payload.extend_from_slice(&1u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
fn pool_owner_fixture(node: &Node) -> policy::Grant {
    let mut grant = fixtures::body();
    let (parent, _) = node.active().unwrap();
    let boot = node.settings.bootstrap_lifecycle_task().unwrap();
    let task = boot.signed.manifest.matrix_task;
    grant.context.network = hex::encode(node.settings.network());
    grant.context.parameters = hex::encode(node.settings.parameters());
    grant.context.actual_parent = hex::encode(parent);
    grant.task.native_task = hex::encode(task);
    grant.task.lease_sha256 = policy::digest_bytes(
        &node
            .lifecycle_task_lease(parent, task, 1)
            .unwrap()
            .encode()
            .unwrap(),
    );
    grant.task.native_model = hex::encode(boot.signed.manifest.model);
    grant.task.native_input = hex::encode(boot.signed.manifest.input);
    grant.limits.operations = 16;
    grant.limits.allocation.cpu_ns *= 8;
    grant.limits.allocation.material_bytes *= 8;
    grant.limits.allocation.da_bytes *= 8;
    grant.limits.allocation.funding_units *= 8;
    grant.declared_funding_units *= 8;
    grant.operation_id =
        policy::operator_operation_id(&grant.context, &grant.exact_packet_sha256).unwrap();
    grant
}
fn attach_pool_owner(
    node: &mut Node,
    journal: &Path,
    grant: policy::Grant,
    permissions: Vec<policy::pool::PoolGrant>,
) {
    let (raw, outside) = fixtures::signed(grant.clone());
    let verified = policy::authenticate(&raw, &outside, grant.not_before_ns + 1).unwrap();
    let policies = permissions
        .into_iter()
        .map(|g| {
            let permission = policy::pool::tests::signed(g);
            std::sync::Arc::new(
                policy::pool::authenticate_pool(
                    &permission,
                    &outside,
                    &verified,
                    grant.not_before_ns + 1,
                )
                .unwrap(),
            )
        })
        .collect();
    node.owner_policy = Some(OwnerPolicy {
        required_marker: verified.marker(journal).unwrap(),
        journal: RefCell::new(policy::Journal::open(journal, fixtures::uid(), &verified).unwrap()),
        policy: std::sync::Arc::new(verified),
        pool_policies: policies,
        outside_keys: (outside.registry_key, outside.task_key),
        unavailable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        epoch: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
    });
}
#[test]
fn exact_pool_permits_restore_real_full_prefix_and_preserve_original_native_state() {
    let dir = fixtures::directory();
    let journal = fixtures::directory();
    let settings = Settings::development_with_profiles(
        None,
        "native-public-evaluation-dev-v1",
        trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let limits = PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: crate::development_public(3).unwrap(),
    };
    let context = node.enable_local_mempool(limits).unwrap();
    let grant = pool_owner_fixture(&node);
    let raw1 = pool_transfer(&settings, 1);
    let raw2 = pool_transfer(&settings, 2);
    let mut p1 = policy::pool::tests::body(&grant, "submit-bundle", std::slice::from_ref(&raw1), 1);
    p1.pool_context = hex::encode(context);
    p1.expected_generation = node.active().unwrap().1;
    p1.operation_id = policy::pool::pool_operation_id(&p1).unwrap();
    let mut p2 = policy::pool::tests::body(&grant, "submit-bundle", std::slice::from_ref(&raw2), 2);
    p2.pool_context = hex::encode(context);
    p2.expected_generation = p1.expected_generation;
    p2.authorized_retained_groups = vec![p1.exact_payload_sha256.clone()];
    p2.operation_id = policy::pool::pool_operation_id(&p2).unwrap();
    attach_pool_owner(&mut node, journal.path(), grant, vec![p1, p2]);
    let active = node.active().unwrap();
    let original = node.state_at(active.0).unwrap();
    let first = node.pool_submit(raw1).unwrap();
    assert_eq!(first.typed_gate_admissions, 1);
    let second = node.pool_submit(raw2).unwrap();
    assert_eq!(second.typed_gate_admissions, 2);
    assert_eq!(second.typed_gate_ready_metadata, 2);
    assert_eq!(node.pool_status_snapshot().unwrap().retained_records, 2);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(node.state_at(active.0).unwrap(), original);
    assert_eq!(
        node.owner_policy
            .as_ref()
            .unwrap()
            .journal
            .borrow()
            .pool_claim_count_for_tests(),
        2
    );
    assert!(node
        .pool_mining_batch(active.0, active.1, 16, 32768)
        .is_err());
}
#[test]
fn unknown_pool_payload_cancels_before_state_reconstruction_or_reservation() {
    let dir = fixtures::directory();
    let journal = fixtures::directory();
    let settings = Settings::development_with_profiles(
        None,
        "native-public-evaluation-dev-v1",
        trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let context = node
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: crate::development_public(3).unwrap(),
        })
        .unwrap();
    let grant = pool_owner_fixture(&node);
    let raw1 = pool_transfer(&settings, 1);
    let raw2 = pool_transfer(&settings, 2);
    let mut p = policy::pool::tests::body(&grant, "submit-bundle", &[raw1], 1);
    p.pool_context = hex::encode(context);
    p.expected_generation = node.active().unwrap().1;
    p.operation_id = policy::pool::pool_operation_id(&p).unwrap();
    attach_pool_owner(&mut node, journal.path(), grant, vec![p]);
    let active = node.active().unwrap();
    let prior = node.pool_status_snapshot().unwrap().retained_records;
    assert_eq!(
        node.pool_submit(raw2).err().unwrap().to_string(),
        "OWNER_POOL_EXACT_COMMAND_REQUIRED"
    );
    assert_eq!(
        node.owner_policy
            .as_ref()
            .unwrap()
            .journal
            .borrow()
            .pool_claim_count_for_tests(),
        0
    );
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(node.pool_status_snapshot().unwrap().retained_records, prior);
}
#[test]
fn old_pool_capability_epoch_is_cancelled_and_never_rewrites_prior_committed_rows() {
    let dir = fixtures::directory();
    let journal = fixtures::directory();
    let settings = Settings::development_with_profiles(
        None,
        "native-public-evaluation-dev-v1",
        trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let context = node
        .enable_local_mempool(PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: crate::development_public(3).unwrap(),
        })
        .unwrap();
    let grant = pool_owner_fixture(&node);
    let raw = pool_transfer(&settings, 1);
    let mut p = policy::pool::tests::body(&grant, "submit-bundle", std::slice::from_ref(&raw), 1);
    p.pool_context = hex::encode(context);
    p.expected_generation = node.active().unwrap().1;
    p.operation_id = policy::pool::pool_operation_id(&p).unwrap();
    attach_pool_owner(&mut node, journal.path(), grant, vec![p]);
    let permit = node
        .begin_owner_pool("submit-bundle", &[raw], context)
        .unwrap()
        .unwrap();
    node.owner_policy
        .as_ref()
        .unwrap()
        .epoch
        .store(2, std::sync::atomic::Ordering::Release);
    assert_eq!(
        permit.progress().err().unwrap().to_string(),
        "OWNER_TASK_VIEW_CHANGED"
    );
    assert_eq!(node.pool_status_snapshot().unwrap().retained_records, 0);
    assert_eq!(
        node.owner_policy
            .as_ref()
            .unwrap()
            .journal
            .borrow()
            .pool_claim_count_for_tests(),
        1
    );
    node.operator_task_accounting_unknown().unwrap();
    assert!(node.recheck_owner_pool(Some(&permit)).is_err());
}

#[test]
fn reserved_work_is_cheaply_held_but_its_private_consumer_and_durable_duplicate_keep_native_truth()
{
    use trnm_crypto_primitives::qualified_work_task::{
        lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    };
    let dir = fixtures::directory();
    let journal = fixtures::directory();
    let settings = Settings::development_with_profiles(
        None,
        "native-public-evaluation-dev-v1",
        trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    let parent = node.active().unwrap().0;
    let boot = settings.bootstrap_lifecycle_task().unwrap();
    let (model, input, a, b) = settings.bootstrap_task_material().unwrap();
    let material = TaskMaterial {
        model: &model,
        input: &input,
        a: &a,
        b: &b,
    };
    let admission =
        verify_lifecycle_admission(&boot.signed.encode().unwrap(), material, &boot.lease, 1)
            .unwrap();
    let mut positive_nonce_packet = None;
    // Exactly eight legal timestamps are allowed for this source fixture.
    // Exhaustion fails the test; it never changes the positive-nonce policy.
    for timestamp_offset in 0..8u64 {
        let material = TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        };
        let candidate = node
            .make_with_task(
                parent,
                Vec::new(),
                crate::development_public(3).unwrap(),
                settings.genesis_time() + 10 + timestamp_offset,
                4096,
                &admission,
                material,
            )
            .unwrap();
        if candidate.header.nonce > 0 {
            positive_nonce_packet = Some(candidate);
            break;
        }
    }
    let packet =
        positive_nonce_packet.expect("eight legal timestamps produced no positive-nonce winner");
    let mut grant = pool_owner_fixture(&node);
    grant.exact_packet_sha256 = policy::digest_bytes(&packet.encode().unwrap());
    grant.operation_id =
        policy::operator_operation_id(&grant.context, &grant.exact_packet_sha256).unwrap();
    grant.nonce_first = packet.header.nonce;
    grant.nonce_last = packet.header.nonce;
    grant.task.a_sha256 = policy::digest_bytes(&packet.proof[4..4 + pon_work::CELLS * 4]);
    grant.task.b_sha256 =
        policy::digest_bytes(&packet.proof[4 + pon_work::CELLS * 4..4 + pon_work::CELLS * 8]);
    attach_pool_owner(&mut node, journal.path(), grant, Vec::new());
    let permit = node.begin_owner_work(&packet).unwrap();
    assert_eq!(
        node.check_admission_context(&packet, settings.genesis_time() + 20)
            .err()
            .unwrap()
            .to_string(),
        "OWNER_TASK_OPERATION_USED"
    );
    let checked = node
        .attach_owner_work(WorkCheckedPacket::verify(packet.clone()).unwrap(), permit)
        .unwrap();
    let id = node
        .admit_work_checked(checked, settings.genesis_time() + 20)
        .unwrap();
    let bytes = node.packet(id).unwrap().encode().unwrap();
    assert_eq!(bytes, packet.encode().unwrap());
    assert_eq!(
        node.admit(&packet, settings.genesis_time() + 20).unwrap(),
        id
    );
    assert_eq!(node.packet(id).unwrap().encode().unwrap(), bytes);
}
