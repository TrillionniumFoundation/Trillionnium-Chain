//! Actual native replay and process-cut tests on private valueless development stores.
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use trnm_pon_node::{development_public, digest, ingress, Node, Packet, Settings};
use trnm_protocol::pon_wire::{Hash, Header};
const CLOCK: u64 = 1_800_010_000;
fn golden() -> Packet {
    Packet {
        header: Header::decode(include_bytes!(
            "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/header.bin"
        ))
        .unwrap(),
        transactions: vec![include_bytes!(
            "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/transaction.bin"
        )
        .to_vec()],
        proof: include_bytes!("../../../../formal/pon-nakamoto-v1/vectors/accepted-block/work.bin")
            .to_vec(),
    }
}
fn expected() -> Value {
    serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/expected.json"
    ))
    .unwrap()
}
fn open(path: &Path) -> Node {
    Node::open(path, Settings::development(None).unwrap(), 2).unwrap()
}
fn extend(node: &mut Node, parent: Hash, time: u64, miner: u64, activate: bool) -> Packet {
    let packet = node
        .make(
            parent,
            vec![],
            development_public(miner).unwrap(),
            time,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    if activate {
        node.activate(id).unwrap();
    }
    packet
}
#[test]
fn test_golden_native_state_matches_separate_oracle_and_duplicate_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let e = expected();
    assert_eq!(hex::encode(node.settings().genesis()), e["genesis"]);
    assert_eq!(node.stats().unwrap()["state_root"], e["genesis_state_root"]);
    let packet = golden();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    assert_eq!(hex::encode(id), e["block_id"]);
    assert_eq!(node.stats().unwrap()["state_root"], e["post_state_root"]);
    let before = node.stats().unwrap();
    assert_eq!(node.admit(&packet, CLOCK).unwrap(), id);
    node.activate(id).unwrap();
    assert_eq!(node.stats().unwrap(), before);
    let actual = node.read_active().unwrap().2;
    let pairs: Vec<(String, String)> = serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/accepted-block/post-state.json"
    ))
    .unwrap();
    let expected_state: trnm_mvcc_fee::pon_executor::State = pairs
        .into_iter()
        .map(|(k, v)| {
            (
                String::from_utf8(hex::decode(k).unwrap()).unwrap(),
                serde_json::from_slice(&hex::decode(v).unwrap()).unwrap(),
            )
        })
        .collect();
    assert_eq!(actual, expected_state);
    drop(node);
    assert_eq!(open(temp.path()).stats().unwrap(), before);
}
#[test]
fn test_malformed_work_and_changed_duplicate_never_mutate_state() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let before = node.stats().unwrap();
    let mut wrong = golden();
    wrong.proof[100] ^= 1;
    assert!(node.admit(&wrong, CLOCK).is_err());
    assert_eq!(node.stats().unwrap(), before);
    let id = node.admit(&golden(), CLOCK).unwrap();
    node.activate(id).unwrap();
    let before = node.stats().unwrap();
    assert_eq!(
        node.admit(&wrong, CLOCK).unwrap_err().to_string(),
        "DUPLICATE_CONTENT"
    );
    assert_eq!(node.stats().unwrap(), before);
    for bytes in [&[][..], &golden().encode().unwrap()[..317]] {
        assert!(Packet::decode(bytes).is_err());
    }
}
#[test]
fn test_cached_work_never_reuses_an_old_clock_verdict() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let packet = golden();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    assert_eq!(node.admit(&packet, 1).unwrap(), id);
    assert_eq!(
        node.activate_observed(id, 1).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
    let tx = digest(expected()["tx_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        node.confirmation(tx, id, 1).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
    assert!(!node.confirmation(tx, id, CLOCK).unwrap().confirmed);
}
#[test]
fn test_confirmed_transfer_is_removed_by_a_real_heavier_fork() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let packet = golden();
    let included = node.admit(&packet, CLOCK).unwrap();
    node.activate(included).unwrap();
    let mut tip = included;
    for i in 2..=7 {
        tip = extend(&mut node, tip, 1_800_000_000 + i * 10, 0, true)
            .id()
            .unwrap();
    }
    let tx = digest(expected()["tx_id"].as_str().unwrap()).unwrap();
    let confirmed = node.confirmation(tx, included, CLOCK).unwrap();
    assert!(confirmed.confirmed);
    assert_eq!(confirmed.depth, Some(6));
    assert!(!confirmed.finalized && !confirmed.execution_authority);
    let mut fork = node.settings().genesis();
    for i in 1..=8 {
        fork = extend(&mut node, fork, 1_800_000_000 + i * 10, 1, false)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let changed = node.confirmation(tx, included, CLOCK).unwrap();
    assert!(changed.reorged && !changed.confirmed);
    assert_eq!(changed.depth, None);
    assert_ne!(tip, fork);
    assert_eq!(node.stats().unwrap()["height"], 8);
}
#[test]
fn test_native_writer_and_namespace_fences_are_not_optional() {
    let temp = tempfile::tempdir().unwrap();
    let node = open(temp.path());
    assert!(Node::open(temp.path(), Settings::development(None).unwrap(), 1).is_err());
    drop(node);
    assert!(Node::open(temp.path(), Settings::development(Some(123)).unwrap(), 1).is_err());
    let path = temp.path().join("native.sqlite");
    let before = fs::read(&path).unwrap();
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(
            "CREATE TRIGGER injected AFTER INSERT ON metadata BEGIN SELECT 1; END",
            [],
        )
        .unwrap();
    }
    let changed = fs::read(&path).unwrap();
    assert_ne!(before, changed);
    assert!(Node::open(temp.path(), Settings::development(None).unwrap(), 1).is_err());
    assert_eq!(fs::read(path).unwrap(), changed);
}
fn fork_fixture(directory: &Path) -> Hash {
    let mut node = open(&directory.join("store"));
    let base = node.admit(&golden(), CLOCK).unwrap();
    node.activate(base).unwrap();
    let a = extend(&mut node, base, 1_800_000_020, 0, true)
        .id()
        .unwrap();
    extend(&mut node, a, 1_800_000_030, 0, true);
    let b = extend(&mut node, base, 1_800_000_020, 1, false)
        .id()
        .unwrap();
    let b = extend(&mut node, b, 1_800_000_030, 1, false).id().unwrap();
    let last = node
        .make(
            b,
            vec![],
            development_public(1).unwrap(),
            1_800_000_040,
            4096,
        )
        .unwrap();
    fs::write(directory.join("last.packet"), last.encode().unwrap()).unwrap();
    last.id().unwrap()
}
#[test]
#[ignore = "owned subprocess helper, invoked by the process-cut tests"]
fn abrupt_child() {
    let directory = std::env::var("TRNM_TEST_DIRECTORY").expect("owned test directory");
    let fault = std::env::var("TRNM_TEST_CUT").expect("exact cut");
    let mut cut = |name: &str| -> trnm_pon_node::Result<()> {
        if name == fault {
            std::process::exit(86);
        }
        Ok(())
    };
    if fault.starts_with("init-") {
        let _ = Node::open_with_fault(
            &Path::new(&directory).join("store"),
            Settings::development(None).unwrap(),
            1,
            Some(&mut cut),
        )
        .unwrap();
    } else {
        let mut node = open(&Path::new(&directory).join("store"));
        let packet =
            Packet::decode(&fs::read(Path::new(&directory).join("last.packet")).unwrap()).unwrap();
        let id = node.admit(&packet, CLOCK).unwrap();
        if fault == "admitted" {
            std::process::exit(86);
        }
        node.activate_with_fault(id, Some(&mut cut)).unwrap();
    }
    panic!("requested process cut was not reached");
}
fn crash(directory: &Path, cut: &str) {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "abrupt_child", "--nocapture"])
        .env("TRNM_TEST_DIRECTORY", directory)
        .env("TRNM_TEST_CUT", cut)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(86),
        "{cut}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    println!("actual child exit86 at {cut}");
}
#[test]
fn test_initialization_process_cuts_recover_only_the_owned_context() {
    for cut in [
        "init-intent",
        "init-schema",
        "init-before-commit",
        "init-committed",
    ] {
        let temp = tempfile::tempdir().unwrap();
        crash(temp.path(), cut);
        let node = open(&temp.path().join("store"));
        assert_eq!(node.stats().unwrap()["height"], 0);
    }
}
#[test]
fn test_every_reorg_process_cut_and_admission_gap_recovers_once() {
    for cut in [
        "admitted",
        "intent",
        "detach:0",
        "detach:1",
        "attach:2",
        "attach:3",
        "attach:4",
        "before-publish",
        "published",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let expected = fork_fixture(temp.path());
        crash(temp.path(), cut);
        let mut node = open(&temp.path().join("store"));
        assert_eq!(node.active().unwrap().0, expected);
        let before = node.stats().unwrap();
        assert_eq!(before["events"], 8);
        node.recover().unwrap();
        assert_eq!(node.stats().unwrap(), before);
        drop(node);
        let db = rusqlite::Connection::open(temp.path().join("store/native.sqlite")).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(DISTINCT slot) FROM kv", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}
#[test]
fn test_socket_history_uses_real_native_validation_and_separate_stores() {
    let temp = tempfile::tempdir().unwrap();
    let now = ingress::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut source = Node::open(&temp.path().join("source"), settings.clone(), 2).unwrap();
    let mut tip = settings.genesis();
    for i in 1..=4 {
        let packet = source
            .make(
                tip,
                vec![],
                development_public(0).unwrap(),
                now - 100 + i * 10,
                4096,
            )
            .unwrap();
        tip = source.admit(&packet, now).unwrap();
        source.activate(tip).unwrap();
    }
    let expected = source.stats().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = stop.clone();
    let server = std::thread::spawn(move || {
        ingress::serve(listener, source, Duration::from_secs(20), child_stop)
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let head = ingress::call(address, &ingress::Request::Head).unwrap();
        assert_eq!(head["tip"], hex::encode(tip));
        let mut receiver = Node::open(&temp.path().join("receiver"), settings.clone(), 4).unwrap();
        assert_eq!(
            ingress::sync_from(&mut receiver, address, tip, settings.genesis(), 16).unwrap(),
            tip
        );
        assert_eq!(
            receiver.stats().unwrap()["state_root"],
            expected["state_root"]
        );
        assert_eq!(receiver.stats().unwrap()["height"], 4);
        ingress::sync_from(&mut receiver, address, tip, tip, 1).unwrap();
    }));
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap().unwrap();
    assert!(metrics.completed_requests >= 3);
    result.unwrap();
}
#[test]
fn test_native_cli_replays_the_existing_signed_vector_without_a_reference_backend() {
    let temp = tempfile::tempdir().unwrap();
    let packet = temp.path().join("input.packet");
    fs::write(&packet, golden().encode().unwrap()).unwrap();
    let store = temp.path().join("store");
    let result = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args(["submit", "--development", "--store"])
        .arg(&store)
        .args(["--logical-now", &CLOCK.to_string(), "--packet"])
        .arg(packet)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["clock_scope"], "logical-test");
    assert_eq!(
        value["result"]["state"]["state_root"],
        expected()["post_state_root"]
    );
    assert_eq!(open(&store).stats().unwrap()["height"], 1);
}
#[test]
fn test_existing_output_path_cannot_publish_a_new_cli_block() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("owned.data");
    fs::write(&output, b"existing bytes").unwrap();
    let store = temp.path().join("store");
    let result = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args(["mine", "--development", "--store"])
        .arg(&store)
        .args([
            "--logical-now",
            &CLOCK.to_string(),
            "--timestamp",
            "1800000010",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(output).unwrap(), b"existing bytes");
    assert_eq!(open(&store).stats().unwrap()["height"], 0);
}

#[test]
fn test_lower_height_higher_required_work_wins_after_native_retarget() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let mut slow = node.settings().genesis();
    for height in 1..=20 {
        slow = extend(&mut node, slow, 1_800_000_000 + 10 * height, 0, true)
            .id()
            .unwrap();
    }
    assert_eq!(node.stats().unwrap()["height"], 20);
    let mut fast = node.settings().genesis();
    for height in 1..=17 {
        fast = extend(&mut node, fast, 1_800_000_000 + height, 1, false)
            .id()
            .unwrap();
    }
    assert_eq!(node.activate(fast).unwrap(), fast);
    assert_eq!(node.stats().unwrap()["height"], 17);
    assert_ne!(
        node.packet(fast).unwrap().header.target,
        node.packet(slow).unwrap().header.target
    );
    assert_eq!(node.activate(slow).unwrap(), fast);
}
