//! Guard mechanisms only. No unqualified fixture is accepted as original Work.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn node() -> (tempfile::TempDir, tempfile::TempDir, Node) {
    let root = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    let mut node = Node::open(&root.path().join("native"), settings, 1).unwrap();
    let (dir, journal) = history::tests::journal();
    let sink = Arc::new(journal.fault_sink().unwrap());
    let unavailable = journal.unavailable_handle();
    let marker = b"unqualified-guard-mechanism-only".to_vec();
    node.continuous_owner = Some(ContinuousOwner {
        marker,
        view: Arc::new(policy::tests::mechanism_view()),
        journal: Arc::new(Mutex::new(journal)),
        cpu: ServiceMutationCpuDomain::standalone(),
        catalog: Arc::new(policy::tests::mechanism_catalog()),
        epoch: Arc::new(AtomicU64::new(1)),
        view_epoch: 1,
        unavailable,
        active: Arc::new(Mutex::new(None)),
        startup_scope: "aa".repeat(32),
        sink,
    });
    (root, dir, node)
}
#[test]
fn mode4_unknown_packet_is_rejected_before_missing_parent_state_or_work() {
    let (_root, _journal, mut node) = node();
    let before = node.active().unwrap();
    // Legal wire shape only: this zero-proof fixture is not qualified Work.
    // The explicit owner gate must refuse it before missing-parent State lookup.
    let packet = Packet {
        header: trnm_protocol::pon_wire::Header {
            network: node.settings.network(),
            parameters: node.settings.parameters(),
            parent: [0xee; 32],
            height: 1,
            timestamp: crate::ingress::now().unwrap(),
            target: [0xff; 32],
            miner: [1; 32],
            transactions: [0; 32],
            state: [0; 32],
            receipts: [0; 32],
            work_task: [0x10; 32],
            nonce: 1,
        },
        transactions: Vec::new(),
        proof: vec![0; pon_work::PROOF_BYTES],
    };
    let packet = Packet::decode(&packet.encode().unwrap()).unwrap();
    let error = node
        .check_admission_context(&packet, crate::ingress::now().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("OWNER_CONTINUOUS_EXPLICIT_SCOPE_REQUIRED"));
    assert!(!error.contains("PARENT_MISSING"));
    assert_eq!(node.active().unwrap(), before);
    assert!(node.admit(&packet, crate::ingress::now().unwrap()).is_err());
}
#[test]
fn mode4_packet_encoding_precheck_precedes_actual_parent_task_lookup() {
    let (_root, _journal, node) = node();
    let before = node.active().unwrap();
    let zeros = vec![0; pon_work::CELLS];
    let task = pon_work::task_id(&zeros, &zeros).unwrap();
    let view = Arc::new(policy::tests::mechanism_view_with_task(&hex::encode(task)));
    let allocation = view
        .permission("parent-reconcile", &"11".repeat(32))
        .unwrap();
    let permit = Permit {
        view,
        allocation,
        epoch: Arc::new(AtomicU64::new(1)),
        expected_epoch: 1,
        unavailable: Arc::new(AtomicBool::new(false)),
    };
    // Isolate the existing private binding boundary with authenticated mechanism
    // fixtures. This expired test view grants no public execution authority.
    let mut packet = Packet {
        header: trnm_protocol::pon_wire::Header {
            network: node.settings.network(),
            parameters: node.settings.parameters(),
            parent: [0x12; 32],
            height: 1,
            timestamp: crate::ingress::now().unwrap(),
            target: [0xff; 32],
            miner: [1; 32],
            transactions: [0; 32],
            state: [0; 32],
            receipts: [0; 32],
            work_task: task,
            nonce: 1,
        },
        transactions: Vec::new(),
        proof: vec![0; pon_work::PROOF_BYTES],
    };
    assert_eq!(
        node.continuous_actual_packet_binding(&permit, &packet)
            .unwrap_err()
            .to_string(),
        "WORK:Version"
    );
    packet.proof[..4].copy_from_slice(b"PNW1");
    for matrix in 0..3 {
        let offset = 4 + matrix * pon_work::CELLS * 4;
        packet.proof[offset..offset + 4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        assert_eq!(
            node.continuous_actual_packet_binding(&permit, &packet)
                .unwrap_err()
                .to_string(),
            "WORK:Field"
        );
        packet.proof[offset..offset + 4].fill(0);
    }
    packet.proof[4] = 1;
    assert_eq!(
        node.continuous_actual_packet_binding(&permit, &packet)
            .unwrap_err()
            .to_string(),
        "WORK:Task"
    );
    packet.proof[4] = 0;
    // Canonical A/B and a passing claimed ticket reach the original lookup and
    // still reject: there is no such parent and no full Work authority exists.
    assert_eq!(
        node.continuous_actual_packet_binding(&permit, &packet)
            .unwrap_err()
            .to_string(),
        "UNKNOWN_PARENT"
    );
    packet.header.parent = [0xee; 32];
    packet.proof[0] ^= 1;
    assert_eq!(
        node.continuous_actual_packet_binding(&permit, &packet)
            .unwrap_err()
            .to_string(),
        "OWNER_CONTINUOUS_PACKET_TASK"
    );
    assert_eq!(node.active().unwrap(), before);
}

#[test]
fn mode4_original_pool_and_unscoped_activation_recovery_remain_hold() {
    let (_root, _journal, mut node) = node();
    let before = node.active().unwrap();
    assert!(node.pool_reconcile().is_err());
    assert!(node.continuous_activation_gate([0xee; 32]).is_err());
    assert!(node.recover().is_err());
    assert_eq!(node.active().unwrap(), before);
}
#[test]
fn mode4_receiver_uses_exact_owner_cpu_domain_and_epoch_cancel_stays_installed() {
    let (_root, _journal, node) = node();
    let original = node.continuous_cpu_domain().unwrap();
    assert!(node.continuous_domain_matches(&original));
    let mut node = node;
    node.bind_public_service_cpu_domain(&original).unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    assert_eq!(
        node.bind_public_service_cpu_domain(&ServiceMutationCpuDomain::standalone())
            .unwrap_err()
            .to_string(),
        "OWNER_CONTINUOUS_SERVICE_CPU_DOMAIN"
    );
    assert!(!node.continuous_domain_matches(&ServiceMutationCpuDomain::standalone()));
    assert!(node.cancel_continuous_epoch().unwrap());
    assert!(!node.cancel_continuous_epoch().unwrap());
    let owner = node.continuous_owner.as_ref().unwrap();
    assert!(owner
        .permission("parent-reconcile", &owner.view.body.actual_parent)
        .is_err());
}
#[test]
fn mode4_actual_receiver_binding_rejects_wrong_declared_lease_model_input_and_ab() {
    let mut task = crate::operator_continuous_test_support::binding().task;
    let lease = b"full original lease bytes fixture";
    let mut proof = vec![0; pon_work::PROOF_BYTES];
    proof[..4].copy_from_slice(b"PNW1");
    let size = pon_work::CELLS * 4;
    task.lease_sha256 = crate::operator_task_policy::digest_bytes(lease);
    task.native_model = hex::encode([0x11; 32]);
    task.native_input = hex::encode([0x22; 32]);
    task.a_sha256 = crate::operator_task_policy::digest_bytes(&proof[4..4 + size]);
    task.b_sha256 = crate::operator_task_policy::digest_bytes(&proof[4 + size..4 + 2 * size]);
    assert!(check_actual_task_fields(
        &task,
        TaskPurpose::Maintenance,
        [0x11; 32],
        [0x22; 32],
        lease,
        &proof
    )
    .is_ok());
    let mut wrong = task.clone();
    wrong.lease_sha256 = "ee".repeat(32);
    assert!(check_actual_task_fields(
        &wrong,
        TaskPurpose::Maintenance,
        [0x11; 32],
        [0x22; 32],
        lease,
        &proof
    )
    .is_err());
    wrong = task.clone();
    wrong.native_model = "ee".repeat(32);
    assert!(check_actual_task_fields(
        &wrong,
        TaskPurpose::Maintenance,
        [0x11; 32],
        [0x22; 32],
        lease,
        &proof
    )
    .is_err());
    wrong = task.clone();
    wrong.native_input = "ee".repeat(32);
    assert!(check_actual_task_fields(
        &wrong,
        TaskPurpose::Maintenance,
        [0x11; 32],
        [0x22; 32],
        lease,
        &proof
    )
    .is_err());
    proof[4] ^= 1;
    assert!(check_actual_task_fields(
        &task,
        TaskPurpose::Maintenance,
        [0x11; 32],
        [0x22; 32],
        lease,
        &proof
    )
    .is_err());
}
#[test]
fn mode4_persistent_mode_marker_refuses_unrestricted_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("native");
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    // Install the protected marker in a genuinely fresh namespace. Opening
    // an unrestricted database first would correctly reject mode installation.
    Node::install_mining_marker(
        &path,
        rustix::process::geteuid().as_raw(),
        b"new-mode4-marker",
    )
    .unwrap();
    assert!(Node::open(&path, settings, 1).is_err());
    assert!(!path.join("native.sqlite").exists());
    let marker = fs::metadata(path.join("owner-task-policy.required")).unwrap();
    assert_eq!(marker.permissions().mode() & 0o777, 0o600);
}
#[test]
fn mode4_dropped_control_frame_persists_unknown_without_a_refund() {
    let (_root, _journal, node) = node();
    let owner = node.continuous_owner.as_ref().unwrap();
    let before = owner.journal.lock().unwrap().usage_digest().unwrap();
    let frame = node.begin_continuous_control_frame().unwrap();
    drop(frame);
    assert!(owner.unavailable.load(Ordering::Acquire));
    assert_eq!(
        owner.journal.lock().unwrap().usage_digest().unwrap(),
        before
    );
    assert!(node.begin_continuous_control_frame().is_err());
}

#[test]
fn mode5_unknown_pool_bundle_is_refused_before_native_state_and_claim_without_borrowing_search() {
    let (_root, _directory, mut node) = node();
    let active = node.active().unwrap();
    let before = node.continuous_journal_head().unwrap();
    let domain = node.continuous_cpu_domain().unwrap();
    let original = domain.begin().unwrap();
    let error = node
        .begin_continuous_public_pool_scope(&[vec![0; 159]], [1; 32], original.checkpoint_handle())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("OWNER_CONTINUOUS_EXACT_POOL_OPERATION_REQUIRED"));
    assert!(!error.contains("PARENT_MISSING"));
    let actual = original.finish();
    assert!(!actual.accounting_unavailable);
    assert!(node
        .operate_owned_continuous_pool(
            &"ee".repeat(32),
            crate::operator_continuous_pool::Command::Reconcile {}
        )
        .is_err());
    assert!(node.continuous_pool_validation_permit().is_err());
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(node.continuous_journal_head().unwrap(), before);
    assert!(node.pool_reconcile().is_err());
    assert!(node.continuous_pool_snapshot().is_err());
}

// Only an existing SQLite metadata key is used; this fixture is a normal
// Node and does not synthesize an authenticated continuous-operation ledger.
fn ordinary_v3_epoch_node() -> (tempfile::TempDir, Settings, Node) {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    let node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    (dir, settings, node)
}

#[test]
fn ordinary_public_v3_unclean_open_retains_one_durable_unknown_cpu_epoch() {
    let (dir, settings, mut node) = ordinary_v3_epoch_node();
    let before = node.stats().unwrap();
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    // This drop models a missing normal close receipt only. No kill, host
    // reboot or claim of exact historical CPU consumption is invented here.
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(reopened.stats().unwrap(), before);
    assert_eq!(
        reopened
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
    assert!(reopened.public_service_epoch_listeners == 0);
}

#[test]
fn ordinary_public_v3_clean_sole_or_last_listener_removes_original_sqlite_marker() {
    let (dir, settings, mut node) = ordinary_v3_epoch_node();
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    assert_eq!(node.public_service_epoch_listeners, 2);
    node.finish_ordinary_public_service_epoch(true).unwrap();
    assert_eq!(node.public_service_epoch_listeners, 1);
    // A crash with one other real listener still open cannot invent clean.
    drop(node);
    let mut reopened = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(
        reopened
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
    drop(reopened);
    // A fresh separate store that ends ALL listeners can reopen normally.
    let (new_dir, new_settings, mut complete) = ordinary_v3_epoch_node();
    complete.begin_ordinary_public_service_epoch().unwrap();
    complete.begin_ordinary_public_service_epoch().unwrap();
    complete.finish_ordinary_public_service_epoch(true).unwrap();
    complete.finish_ordinary_public_service_epoch(true).unwrap();
    assert_eq!(complete.public_service_epoch_listeners, 0);
    drop(complete);
    let mut clean = Node::open(new_dir.path(), new_settings, 1).unwrap();
    assert!(clean.begin_ordinary_public_service_epoch().unwrap());
    clean.finish_ordinary_public_service_epoch(true).unwrap();
}

#[test]
fn ordinary_public_v3_one_listener_close_while_other_cpu_is_in_flight_does_not_poison_epoch() {
    let (dir, settings, mut node) = ordinary_v3_epoch_node();
    node.begin_ordinary_public_service_epoch().unwrap();
    node.begin_ordinary_public_service_epoch().unwrap();
    // When listener A finishes but B is still spending its original CPU
    // reservation, global available credit/in-flight need not be clean.
    // A has joined its own workers; only B can settle the FINAL epoch.
    node.finish_ordinary_public_service_epoch(false).unwrap();
    assert!(!node.public_service_epoch_unknown);
    assert_eq!(node.public_service_epoch_listeners, 1);
    node.finish_ordinary_public_service_epoch(true).unwrap();
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert!(reopened.begin_ordinary_public_service_epoch().unwrap());
    reopened.finish_ordinary_public_service_epoch(true).unwrap();
}

#[test]
fn ordinary_public_v3_unknown_clock_and_corrupt_marker_never_clear_on_restart() {
    let (dir, settings, mut node) = ordinary_v3_epoch_node();
    node.begin_ordinary_public_service_epoch().unwrap();
    node.mark_ordinary_public_service_epoch_unknown();
    // Final service result remains the original business result; only
    // future cold service admission is refused by its durable marker.
    node.finish_ordinary_public_service_epoch(true).unwrap();
    assert!(node.public_service_epoch_unknown);
    assert_eq!(node.public_service_epoch_listeners, 0);
    drop(node);
    let mut reopened = Node::open(dir.path(), settings.clone(), 1).unwrap();
    assert_eq!(
        reopened
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
    // A malformed existing metadata value is never treated as a clean
    // absence, even though it is not a valid native operation receipt.
    drop(reopened);
    let db = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    db.execute(
        "UPDATE metadata SET value=X'00' WHERE key='ordinary-public-v3-epoch-v1'",
        [],
    )
    .unwrap();
    drop(db);
    let mut malformed = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(
        malformed
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
}

#[test]
fn continuous_owner_keeps_original_authenticated_journal_not_ordinary_marker() {
    let (_root, _history, mut node) = node();
    assert!(!node.begin_ordinary_public_service_epoch().unwrap());
    node.finish_ordinary_public_service_epoch(true).unwrap();
    assert_eq!(node.public_service_epoch_listeners, 0);
}
