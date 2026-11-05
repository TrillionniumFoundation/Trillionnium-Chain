//! Actual KV, native work/admission and unchanged complete M06 parity.
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    pon_commitment::CommitmentMethod,
    pon_executor::{self, Config, State},
};
use trnm_pon_node::{development_public, maintenance, sequence_root, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};
const NOW: u64 = 10000;
type CanonicalDelta = (String, Option<Vec<u8>>, Option<Vec<u8>>);
fn public(who: u64) -> Hash {
    let key = signing_key_from_hex(&hex::encode(hash(
        b"derived-recipient",
        &[&who.to_le_bytes()],
    )))
    .unwrap();
    key.verifying_key().to_bytes()
}
fn transfer(settings: &Settings, nonce: u64, destination: Hash) -> Vec<u8> {
    let mut payload = destination.to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 900,
        fee_limit: 1000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn make(node: &Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>, miner: u64) -> Packet {
    let packet = node
        .make(
            parent,
            txs,
            development_public(miner).unwrap(),
            1 + height * 10,
            4096,
        )
        .unwrap();
    assert_eq!(packet.header.network, node.settings().network());
    assert_eq!(packet.header.parameters, node.settings().parameters());
    assert_eq!(packet.header.parent, parent);
    assert_eq!(packet.header.height, height);
    assert_eq!(packet.header.miner, development_public(miner).unwrap());
    assert_eq!(packet.header.timestamp, 1 + height * 10);
    packet
}
fn complete(parent: &State, packet: &Packet, settings: &Settings) -> pon_executor::Output {
    let mut config = Config::installed().unwrap();
    let label = format!("trnm-pon-native-wall-devnet-3-{}", settings.genesis_time());
    config.params["genesis_timestamp"] = json!(settings.genesis_time());
    config.params["chain_label"] = json!(label);
    config.network = hash(b"network", &[label.as_bytes()]);
    let wire: Value =
        serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json")).unwrap();
    let work: Value =
        serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json")).unwrap();
    config.parameters = hash(
        b"parameters",
        &[
            &serde_json::to_vec(&config.params).unwrap(),
            &serde_json::to_vec(&wire).unwrap(),
            &serde_json::to_vec(&work).unwrap(),
            &serde_json::to_vec(&config.model_registry).unwrap(),
        ],
    );
    assert_eq!(config.network, settings.network());
    assert_eq!(config.parameters, settings.parameters());
    assert_eq!(packet.header.network, settings.network());
    assert_eq!(packet.header.parameters, settings.parameters());
    pon_executor::execute(
        parent,
        &packet.transactions,
        packet.header.height,
        packet.header.miner,
        packet.header.parent,
        1,
        &config,
    )
    .unwrap()
}
fn delta_check(db: &Connection, id: Hash, before: &State, after: &State) {
    let mut stmt = db
        .prepare("SELECT key,before,after FROM deltas WHERE block=? ORDER BY key")
        .unwrap();
    let actual: Vec<CanonicalDelta> = stmt
        .query_map([id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut keys: std::collections::BTreeSet<_> = before.keys().collect();
    keys.extend(after.keys());
    let expected: Vec<_> = keys
        .into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| {
            (
                key.clone(),
                before.get(key).map(|v| serde_json::to_vec(v).unwrap()),
                after.get(key).map(|v| serde_json::to_vec(v).unwrap()),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}
#[test]
fn inactive_extensions_full_state_receipts_deltas_and_reopen_match_complete_execution() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(temp.path(), settings.clone(), 4).unwrap();
    let genesis = settings.genesis();
    let original = node.read_active().unwrap();
    let mut state = original.2.clone();
    let mut parent = genesis;
    let db = Connection::open(temp.path().join("native.sqlite")).unwrap();
    for height in 1..=9 {
        let packet = make(
            &node,
            parent,
            height,
            vec![transfer(&settings, height, public(height))],
            3,
        );
        let expected = complete(&state, &packet, &settings);
        assert_eq!(packet.header.state, expected.root);
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &expected.receipts)
        );
        assert_eq!(
            node.derived_commitment_status().cache_root,
            Some(pon_executor::root(&original.2).unwrap())
        );
        let id = node.admit(&packet, NOW).unwrap();
        delta_check(&db, id, &state, &expected.state);
        assert_eq!(node.state_at(id).unwrap(), expected.state);
        assert_eq!(node.active().unwrap().0, genesis);
        assert_eq!(
            node.derived_commitment_status().cache_root,
            Some(pon_executor::root(&original.2).unwrap())
        );
        state = expected.state;
        parent = id;
    }
    node.activate_observed(parent, NOW).unwrap();
    assert_eq!(node.read_active().unwrap().2, state);
    let before = node.read_active().unwrap();
    drop(node);
    drop(db);
    let node = Node::open(temp.path(), settings, 4).unwrap();
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(
        node.derived_commitment_status().cache_root,
        Some(pon_executor::root(&state).unwrap())
    );
}
#[test]
fn warm_cache_still_reads_same_tip_actual_kv_and_rejects_external_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = Node::open(temp.path(), settings, 1).unwrap();
    let original = node.read_active().unwrap();
    node.read_active().unwrap();
    assert_eq!(
        node.derived_commitment_status().last.unwrap().method,
        CommitmentMethod::CheckedApply
    );
    let db = Connection::open(temp.path().join("native.sqlite")).unwrap();
    let key = format!("account:{}", hex::encode(development_public(0).unwrap()));
    let raw: Vec<u8> = db
        .query_row("SELECT value FROM kv WHERE key=?", [&key], |r| r.get(0))
        .unwrap();
    let slot: u64 = db
        .query_row("SELECT state_slot FROM active", [], |r| r.get(0))
        .unwrap();
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["balance"] = json!(changed["balance"].as_u64().unwrap() + 1);
    db.execute(
        "UPDATE kv SET value=? WHERE slot=? AND key=?",
        params![serde_json::to_vec(&changed).unwrap(), slot, key],
    )
    .unwrap();
    assert_eq!(node.read_active().unwrap_err().to_string(), "ROOT");
    db.execute(
        "UPDATE kv SET value=? WHERE slot=? AND key=?",
        params![raw, slot, key],
    )
    .unwrap();
    assert_eq!(node.read_active().unwrap(), original);
    db.execute(
        "INSERT INTO kv VALUES(?,?,?)",
        params![slot, "extra", b"0".as_slice()],
    )
    .unwrap();
    assert_eq!(node.read_active().unwrap_err().to_string(), "ROOT");
    db.execute("DELETE FROM kv WHERE key='extra'", []).unwrap();
    assert_eq!(node.read_active().unwrap(), original);
    db.execute("DELETE FROM kv WHERE slot=? AND key=?", params![slot, key])
        .unwrap();
    assert_eq!(node.read_active().unwrap_err().to_string(), "ROOT");
    let restored = serde_json::to_vec(&original.2[&key]).unwrap();
    db.execute("INSERT INTO kv VALUES(?,?,?)", params![slot, key, restored])
        .unwrap();
    assert_eq!(node.read_active().unwrap(), original);
    db.execute(
        "UPDATE kv SET value=? WHERE slot=? AND key=?",
        params![b" 0".as_slice(), slot, key],
    )
    .unwrap();
    assert_eq!(node.read_active().unwrap_err().to_string(), "STATE_BYTES");
}
#[test]
fn valid_proof_wrong_state_and_sql_failure_never_publish_staged_cache() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(temp.path(), settings.clone(), 2).unwrap();
    let before = node.read_active().unwrap();
    let root = pon_executor::root(&before.2).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        1,
        vec![transfer(&settings, 1, public(1))],
        3,
    );
    let mut wrong = packet.clone();
    wrong.header.state = [9; 32];
    let (a, b) = maintenance();
    let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        wrong.header.nonce = nonce;
        let proof = prepared.prove(wrong.header.challenge()).unwrap();
        if hash(
            b"ticket",
            &[&wrong.header.challenge(), &proof[proof.len() - 32..]],
        ) <= wrong.header.target
        {
            wrong.proof = proof;
            break;
        }
    }
    pon_work::verify(
        wrong.header.challenge(),
        wrong.header.work_task,
        wrong.header.target,
        &wrong.proof,
    )
    .unwrap();
    assert_eq!(node.admit(&wrong, NOW).unwrap_err().to_string(), "ROOT");
    assert_eq!(node.read_active().unwrap(), before);
    let db = Connection::open(temp.path().join("native.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_delta BEFORE INSERT ON deltas BEGIN SELECT RAISE(ABORT,'derived SQL fault');END;").unwrap();
    assert!(node.admit(&packet, NOW).is_err());
    assert_eq!(node.derived_commitment_status().cache_root, Some(root));
    assert_eq!(node.read_active().unwrap(), before);
    db.execute_batch("DROP TRIGGER fail_delta").unwrap();
    let id = node.admit(&packet, NOW).unwrap();
    assert_eq!(node.derived_commitment_status().cache_root, Some(root));
    db.execute_batch("CREATE TRIGGER fail_activate BEFORE UPDATE ON active BEGIN SELECT RAISE(ABORT,'activate fault');END;").unwrap();
    assert!(node.activate(id).is_err());
    assert_eq!(node.derived_commitment_status().cache_root, Some(root));
    assert_eq!(node.read_active().unwrap(), before);
    db.execute_batch("DROP TRIGGER fail_activate").unwrap();
    node.activate(id).unwrap();
    let actual = node.read_active().unwrap();
    assert_eq!(
        node.derived_commitment_status().cache_root,
        Some(pon_executor::root(&actual.2).unwrap())
    );
}
#[test]
fn actual_heavier_fork_cut_invalidates_then_recovers_full_canonical_state() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(temp.path(), settings.clone(), 2).unwrap();
    let genesis = settings.genesis();
    let mut main = genesis;
    for height in 1..=2 {
        let packet = make(
            &node,
            main,
            height,
            vec![transfer(&settings, height, public(height))],
            3,
        );
        main = node.admit(&packet, NOW).unwrap();
        node.activate(main).unwrap();
    }
    let mut fork = genesis;
    let mut expected = node.state_at(genesis).unwrap();
    for height in 1..=3 {
        let packet = make(
            &node,
            fork,
            height,
            vec![transfer(&settings, height, public(100 + height))],
            4,
        );
        expected = complete(&expected, &packet, &settings).state;
        fork = node.admit(&packet, NOW).unwrap();
    }
    let mut cut = |where_: &str| -> trnm_pon_node::Result<()> {
        if where_ == "detach:0" {
            Err("intentional recovery cut".into())
        } else {
            Ok(())
        }
    };
    assert!(node.activate_with_fault(fork, Some(&mut cut)).is_err());
    assert_eq!(node.derived_commitment_status().cache_root, None);
    drop(node);
    let mut node = Node::open(temp.path(), settings, 2).unwrap();
    assert_eq!(node.active().unwrap().0, fork);
    assert_eq!(node.read_active().unwrap().2, expected);
    node.recover().unwrap();
    assert_eq!(node.read_active().unwrap().2, expected);
    assert!(!expected.contains_key(&format!("account:{}", hex::encode(public(1)))));
}
#[test]
fn actual_valid_growth_above_previous_8192_budget_keeps_checked_snapshot_and_reopens() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(temp.path(), settings.clone(), 2).unwrap();
    let mut parent = settings.genesis();
    let mut expected = node.read_active().unwrap().2;
    for height in 1..=32 {
        let txs = (0..256)
            .map(|i| {
                let nonce = (height - 1) * 256 + i + 1;
                transfer(&settings, nonce, public(nonce))
            })
            .collect();
        let packet = make(&node, parent, height, txs, 3);
        let full = complete(&expected, &packet, &settings);
        assert_eq!(packet.header.state, full.root);
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &full.receipts)
        );
        parent = node.admit(&packet, NOW).unwrap();
        node.activate_observed(parent, NOW).unwrap();
        expected = full.state;
        assert_eq!(node.read_active().unwrap().2, expected);
    }
    assert!(expected.len() > 8192);
    let status = node.derived_commitment_status();
    assert_eq!(
        status.cache_root,
        Some(pon_executor::root(&expected).unwrap())
    );
    assert_eq!(status.last.unwrap().method, CommitmentMethod::CheckedApply);
    assert_eq!(
        expected[&format!("account:{}", hex::encode(development_public(0).unwrap()))]["nonce"],
        8192
    );
    let before = node.read_active().unwrap();
    drop(node);
    let node = Node::open(temp.path(), settings, 2).unwrap();
    assert_eq!(node.read_active().unwrap(), before);
}
