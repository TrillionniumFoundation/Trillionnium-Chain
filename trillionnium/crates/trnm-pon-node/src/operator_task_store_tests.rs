//! Source-only mechanism tests, not an authorized positive Native packet fixture.
use super::*;
use crate::operator_task_policy::{self as policy, tests as fixtures};

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
        "OWNER_TASK_POOL_PREVIEW_PENDING"
    );
    assert_eq!(
        node.pool_reconcile().err().unwrap().to_string(),
        "OWNER_TASK_POOL_PREVIEW_PENDING"
    );
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(count(&node), pool_before);
    assert!(!fs::read_dir(journal_dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("claim-")));
}
