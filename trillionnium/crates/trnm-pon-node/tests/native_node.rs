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
    assert_eq!(
        node.admit(&packet, 1).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
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

fn signed_transfer(settings: &Settings, sender: u64, nonce: u64) -> Vec<u8> {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::{hash, Envelope};
    let seed = hash(b"DEV-ONLY-KEY", &[&sender.to_le_bytes()]);
    let key = signing_key_from_hex(&hex::encode(seed)).unwrap();
    let mut payload = development_public(sender + 20).unwrap().to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(sender).unwrap(),
        nonce,
        expiry: 10000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn batch_fixture(path: &Path, settings: Settings) -> (Node, Vec<(Hash, Hash)>) {
    let mut node = Node::open(path, settings.clone(), 2).unwrap();
    let txs: Vec<_> = (0..4).map(|i| signed_transfer(&settings, i, 1)).collect();
    let packet = node
        .make(
            settings.genesis(),
            txs.clone(),
            development_public(0).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let included = node.admit(&packet, CLOCK).unwrap();
    node.activate(included).unwrap();
    let queries = txs
        .iter()
        .map(|tx| (trnm_protocol::pon_wire::hash(b"tx-id", &[tx]), included))
        .collect();
    let mut tip = included;
    for height in 2..=7 {
        tip = extend(
            &mut node,
            tip,
            settings.genesis_time() + height * 10,
            0,
            true,
        )
        .id()
        .unwrap();
    }
    (node, queries)
}
#[test]
fn test_native_batch_checks_one_history_and_one_shared_body() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    let batch = node.confirmations(&queries, CLOCK).unwrap();
    assert_eq!(batch.ancestry_checked, 7);
    assert_eq!(batch.distinct_bodies_checked, 1);
    assert_eq!(batch.observations.len(), 4);
    for (query, observation) in queries.iter().zip(batch.observations) {
        assert!(
            observation.confirmed && !observation.finalized && !observation.execution_authority
        );
        assert_eq!(observation.depth, Some(6));
        assert_eq!(
            serde_json::to_value(&observation).unwrap(),
            serde_json::to_value(node.confirmation(query.0, query.1, CLOCK).unwrap()).unwrap()
        );
    }
}
#[test]
fn test_native_batch_invalid_tail_duplicate_and_limits_return_no_partial_success() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    let before = node.stats().unwrap();
    assert_eq!(
        node.confirmations(&[], CLOCK).unwrap_err().to_string(),
        "CONFIRMATION_LIMIT"
    );
    assert_eq!(
        node.confirmations(&vec![queries[0]; 257], CLOCK)
            .unwrap_err()
            .to_string(),
        "CONFIRMATION_LIMIT"
    );
    assert_eq!(
        node.confirmations(&[queries[0], queries[0]], CLOCK)
            .unwrap_err()
            .to_string(),
        "DUPLICATE_QUERY"
    );
    let mut wrong = queries.clone();
    wrong.last_mut().unwrap().0 = [255; 32];
    assert_eq!(
        node.confirmations(&wrong, CLOCK).unwrap_err().to_string(),
        "MEMBERSHIP"
    );
    assert_eq!(node.stats().unwrap(), before);
}
#[test]
fn test_native_batch_and_history_cancel_after_traversal_without_writes_or_cache() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    let before = node.stats().unwrap();
    let mut stop = |n| -> trnm_pon_node::Result<()> {
        if n == 7 {
            Err("CANCELLED".into())
        } else {
            Ok(())
        }
    };
    assert_eq!(
        node.confirmations_with_progress(&queries, CLOCK, &mut stop)
            .unwrap_err()
            .to_string(),
        "CANCELLED"
    );
    assert_eq!(
        node.history_with_progress(
            node.active().unwrap().0,
            node.settings().genesis(),
            16,
            &mut stop
        )
        .unwrap_err()
        .to_string(),
        "CANCELLED"
    );
    assert_eq!(node.stats().unwrap(), before);
    assert_eq!(
        node.confirmations(&queries, 1).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
    assert_eq!(
        node.confirmations(&queries, CLOCK)
            .unwrap()
            .ancestry_checked,
        7
    );
}
#[test]
fn test_native_batch_rechecks_future_ancestor_below_all_inclusions() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = open(temp.path());
    let base = node.settings().genesis_time();
    let mut tip = node.settings().genesis();
    for height in 1..=8 {
        let timestamp = base + if height == 8 { 1000 } else { height * 10 };
        tip = extend(&mut node, tip, timestamp, 0, true).id().unwrap();
    }
    let tx = signed_transfer(node.settings(), 1, 1);
    let packet = node
        .make(
            tip,
            vec![tx.clone()],
            development_public(0).unwrap(),
            base + 90,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, CLOCK).unwrap();
    node.activate(id).unwrap();
    let queries = [(trnm_protocol::pon_wire::hash(b"tx-id", &[&tx]), id)];
    assert!(node.confirmations(&queries, CLOCK).is_ok());
    assert_eq!(
        node.confirmations(&queries, base + 200)
            .unwrap_err()
            .to_string(),
        "TIME_DEFERRED"
    );
}
#[test]
fn test_native_batch_generation_change_is_detected_before_any_response() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    // Inject only the final generation-race check, not a claimed independent reorg.
    let db = rusqlite::Connection::open(temp.path().join("native.sqlite")).unwrap();
    let mut change = |n| -> trnm_pon_node::Result<()> {
        if n == 7 {
            db.execute("UPDATE active SET generation=generation+1", [])
                .unwrap();
        }
        Ok(())
    };
    assert_eq!(
        node.confirmations_with_progress(&queries, CLOCK, &mut change)
            .unwrap_err()
            .to_string(),
        "STALE_VIEW"
    );
}
#[test]
fn test_native_batch_actual_heavier_reorg_removes_all_confirmations() {
    let temp = tempfile::tempdir().unwrap();
    let (mut node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    assert!(node
        .confirmations(&queries, CLOCK)
        .unwrap()
        .observations
        .iter()
        .all(|o| o.confirmed));
    let mut fork = node.settings().genesis();
    for height in 1..=8 {
        fork = extend(&mut node, fork, 1_800_000_000 + height * 10, 1, false)
            .id()
            .unwrap();
    }
    node.activate(fork).unwrap();
    let batch = node.confirmations(&queries, CLOCK).unwrap();
    assert!(batch
        .observations
        .iter()
        .all(|o| o.reorged && !o.confirmed && o.depth.is_none()));
    assert_eq!(batch.ancestry_checked, 8);
}
#[test]
fn test_native_batch_cli_uses_the_real_persisted_owner() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store");
    let (node, queries) = batch_fixture(&store, Settings::development(None).unwrap());
    let expected = serde_json::to_value(node.confirmations(&queries, CLOCK).unwrap()).unwrap();
    drop(node);
    let input: Vec<_> = queries.iter().map(|(transaction, block)| serde_json::json!({"transaction":hex::encode(transaction),"block":hex::encode(block)})).collect();
    let path = temp.path().join("queries.json");
    fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args(["confirm-batch", "--development", "--store"])
        .arg(store)
        .args(["--logical-now", &CLOCK.to_string(), "--queries"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let result: Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(result["result"], expected);
    assert_eq!(result["clock_scope"], "logical-test");
}
#[test]
fn test_socket_false_transcripts_and_honest_native_batch_use_the_actual_entry() {
    use trnm_protocol::pon_wire::hash;
    let temp = tempfile::tempdir().unwrap();
    let clock = ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 200)).unwrap();
    let (source, queries) = batch_fixture(temp.path(), settings.clone());
    let expected_tip = source.active().unwrap().0;
    let mut packet = source
        .make(
            expected_tip,
            vec![],
            development_public(0).unwrap(),
            clock - 100,
            4096,
        )
        .unwrap();
    let challenge = packet.header.challenge();
    let original = packet.proof[packet.proof.len() - 32..].to_vec();
    let mut false_packets = Vec::new();
    for i in 0u64..32 {
        let trace = (0u64..4096)
            .map(|n| hash(b"test-false-trace", &[&i.to_le_bytes(), &n.to_le_bytes()]))
            .find(|t| {
                t.as_slice() != original
                    && hash(b"ticket", &[&challenge, t]) <= packet.header.target
            })
            .unwrap();
        let offset = packet.proof.len() - 32;
        packet.proof[offset..].copy_from_slice(&trace);
        false_packets.push(hex::encode(packet.encode().unwrap()));
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = stop.clone();
    let server = std::thread::spawn(move || {
        ingress::serve(listener, source, Duration::from_secs(30), child_stop)
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        std::thread::scope(|scope| {
            let attack = scope.spawn(|| {
                for packet in false_packets {
                    let error = ingress::call(address, &ingress::Request::Submit { packet })
                        .unwrap_err()
                        .to_string();
                    assert!(error.contains("WORK:Transcript"), "{error}");
                }
            });
            for _ in 0..16 {
                let request = ingress::Request::ConfirmMany {
                    queries: queries
                        .iter()
                        .map(|(tx, id)| ingress::ConfirmationQuery {
                            transaction: hex::encode(tx),
                            block: hex::encode(id),
                        })
                        .collect(),
                };
                let batch = ingress::call(address, &request).unwrap();
                assert_eq!(batch["ancestry_checked"], 7);
                assert!(batch["observations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|o| o["confirmed"] == true
                        && o["observed_tip"] == hex::encode(expected_tip)));
            }
            attack.join().unwrap();
        });
    }));
    stop.store(true, Ordering::Release);
    let metrics = server.join().unwrap().unwrap();
    result.unwrap();
    assert_eq!(metrics.rejected_requests, 32);
    assert_eq!(metrics.completed_requests, 16);
    println!("actual native loopback: 32 ticket-passing false transcripts rejected; 16 four-query batches served; not public/Sybil qualification");
}

#[test]
fn test_native_header_projection_rejects_changed_header_or_trace() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    let tip = node.active().unwrap().0;
    let original = node.packet(tip).unwrap().encode().unwrap();
    let db = rusqlite::Connection::open(temp.path().join("native.sqlite")).unwrap();
    for offset in [0, original.len() - 1] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        db.execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            rusqlite::params![changed, tip.as_slice()],
        )
        .unwrap();
        assert!(node.confirmations(&queries, CLOCK).is_err());
        db.execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            rusqlite::params![&original, tip.as_slice()],
        )
        .unwrap();
        assert!(node
            .confirmations(&queries, CLOCK)
            .unwrap()
            .observations
            .iter()
            .all(|o| o.confirmed));
    }
}

#[test]
fn test_native_body_membership_is_still_checked_after_header_projection() {
    let temp = tempfile::tempdir().unwrap();
    let (node, queries) = batch_fixture(temp.path(), Settings::development(None).unwrap());
    let block = queries[0].1;
    let original = node.packet(block).unwrap().encode().unwrap();
    let mut packet = node.packet(block).unwrap();
    packet.transactions[0] = signed_transfer(node.settings(), 1, 100);
    let changed = packet.encode().unwrap();
    let db = rusqlite::Connection::open(temp.path().join("native.sqlite")).unwrap();
    db.execute(
        "UPDATE blocks SET packet=? WHERE id=?",
        rusqlite::params![changed, block.as_slice()],
    )
    .unwrap();
    assert_eq!(
        node.confirmations(&queries, CLOCK).unwrap_err().to_string(),
        "ROOT"
    );
    db.execute(
        "UPDATE blocks SET packet=? WHERE id=?",
        rusqlite::params![&original, block.as_slice()],
    )
    .unwrap();
    assert!(node.confirmations(&queries, CLOCK).is_ok());
}

#[test]
fn test_full_transaction_pages_use_byte_limits_and_recover_all_native_state() {
    let temp = tempfile::tempdir().unwrap();
    let clock = ingress::now().unwrap();
    let settings = Settings::development(Some(clock - 200)).unwrap();
    let mut source = Node::open(&temp.path().join("source"), settings.clone(), 4).unwrap();
    let mut tip = settings.genesis();
    for height in 1u64..=12 {
        let txs = (1..=256)
            .map(|i| signed_transfer(&settings, 1, (height - 1) * 256 + i))
            .collect();
        let packet = source
            .make(
                tip,
                txs,
                development_public(0).unwrap(),
                clock - 200 + height * 10,
                4096,
            )
            .unwrap();
        tip = source.admit(&packet, clock).unwrap();
        source.activate_observed(tip, clock).unwrap();
    }
    let expected_root = source.stats().unwrap()["state_root"].clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = stop.clone();
    let server = std::thread::spawn(move || {
        ingress::serve(listener, source, Duration::from_secs(120), child_stop)
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut receiver = Node::open(&temp.path().join("receiver"), settings.clone(), 4).unwrap();
        let mut after = settings.genesis();
        let mut page_count = 0;
        while after != tip {
            let value = ingress::call(
                address,
                &ingress::Request::History {
                    tip: hex::encode(tip),
                    after: hex::encode(after),
                },
            )
            .unwrap();
            assert!(serde_json::to_vec(&value).unwrap().len() <= 2_097_152);
            let page: ingress::Page = serde_json::from_value(value).unwrap();
            assert!(!page.packets.is_empty());
            if page_count == 0 {
                assert!(!page.complete);
                assert!(page.packets.len() < 12);
            }
            after = ingress::receive_page(&mut receiver, page, tip, after, clock).unwrap();
            page_count += 1;
            assert!(page_count <= 12);
        }
        assert!(page_count >= 2);
        assert_eq!(receiver.stats().unwrap()["state_root"], expected_root);
        assert_eq!(receiver.stats().unwrap()["height"], 12);
        drop(receiver);
        assert_eq!(
            Node::open(&temp.path().join("receiver"), settings, 1)
                .unwrap()
                .stats()
                .unwrap()["state_root"],
            expected_root
        );
    }));
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    result.unwrap();
}
