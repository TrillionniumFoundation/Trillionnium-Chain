//! Actual native admission tests. The large fixture explicitly preallocates
//! dormant zero-balance genesis accounts below the old limit; only signed,
//! fully proved successor transactions cross it. It is not synthetic history.
use super::*;
use crate::{development_public, ErrorCode, Packet};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::hash;

fn base_settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}
fn settings() -> Settings {
    base_settings()
        .with_permanent_account_growth_v2("native-growth-v2-test")
        .unwrap()
}
fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn signed(settings: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(sender),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn transfer(settings: &Settings, sender: u64, nonce: u64, recipient: Hash, amount: u64) -> Vec<u8> {
    let mut payload = recipient.to_vec();
    payload.extend(amount.to_le_bytes());
    signed(settings, sender, nonce, 1, payload)
}
fn make(node: &Node, parent: Hash, txs: Vec<Vec<u8>>) -> GrowthPacket {
    let height = node.record(parent).unwrap().height + 1;
    node.make_growth_consensus_maintenance(parent, txs, public(3), 1 + height * 10, 4096)
        .unwrap()
}
fn admit(node: &mut Node, packet: &GrowthPacket) -> Hash {
    let id = node.admit_growth(packet, 100_000).unwrap();
    assert_eq!(node.activate(id).unwrap(), id);
    id
}
fn reseal(packet: &mut GrowthPacket) {
    packet.header.witness = GrowthPacket::witness_digest(&packet.accounts).unwrap();
    let (a, b) = continuity_v1::maintenance_matrices();
    let task = pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        packet.header.ledger.nonce = nonce;
        packet.proof = task.prove(packet.header.challenge()).unwrap();
        if pon_work::verify(
            packet.header.challenge(),
            packet.header.ledger.work_task,
            packet.header.ledger.target,
            &packet.proof,
        )
        .is_ok()
        {
            return;
        }
    }
    panic!("finite work search exhausted");
}
fn rows(db: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut values: Vec<Vec<String>> = statement
                .query_map([], |r| {
                    (0..columns)
                        .map(|i| {
                            r.get::<_, rusqlite::types::Value>(i)
                                .map(|v| format!("{v:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            values.sort();
            (table, values)
        })
        .collect()
}
fn reference(settings: &Settings, state: &State, packet: &GrowthPacket) -> State {
    let original = growth_commitment_from_complete_state_v2(settings, state).unwrap();
    let partition = limits::AccountPartition {
        parent_count: original.permanent_account_count,
        parent_balance: original.permanent_account_balance,
    };
    let h = &packet.header.ledger;
    let out = limits::execute_with_commitment(
        state,
        pon_executor::BlockExecution {
            transactions: &packet.transactions,
            height: h.height,
            miner: h.miner,
            parent_id: h.parent,
            workers: 1,
        },
        &settings.app,
        &partition,
        &|_| Ok(()),
        |_, next| {
            growth_commitment_from_complete_state_v2(settings, next)
                .map(|s| s.id)
                .map_err(|_| "REFERENCE_ROOT")
        },
        &|_| Ok::<_, Error>(()),
    )
    .unwrap();
    assert_eq!(out.root, h.state);
    assert_eq!(sequence_root("receipts", &out.receipts), h.receipts);
    out.state
}
fn assert_reference(node: &Node, id: Hash, expected: &State) {
    let full = growth_commitment_from_complete_state_v2(node.settings(), expected).unwrap();
    assert_eq!(
        node.growth_observe(id).unwrap().commitment,
        *full.observation()
    );
    assert_eq!(node.growth_working(id).unwrap(), working(expected));
    for (owner, value) in archive::accounts(expected).unwrap() {
        // Small reference fixture only; large tests use separate bounded queries.
        assert_eq!(node.growth_account(id, owner).unwrap(), Some(value));
    }
}

#[test]
fn native_growth_v2_signed_branches_nonce_obligations_and_cold_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let genesis = settings.genesis();
    assert!(node.read_active().is_err());
    assert!(node.state_at(genesis).is_err());
    let initial = settings.initial.clone();
    let first = make(
        &node,
        genesis,
        vec![transfer(&settings, 0, 1, public(10), 100_000)],
    );
    assert!(Packet::decode(&first.encode().unwrap()).is_err());
    let first_state = reference(&settings, &initial, &first);
    let first_id = admit(&mut node, &first);
    assert_reference(&node, first_id, &first_state);
    let second = make(
        &node,
        first_id,
        vec![transfer(&settings, 0, 2, public(11), 100_000)],
    );
    let second_state = reference(&settings, &first_state, &second);
    let second_id = admit(&mut node, &second);
    let generation = node.active().unwrap().1;
    let mut fork = genesis;
    let mut full = initial;
    for height in 1..=3 {
        let packet = make(
            &node,
            fork,
            vec![transfer(&settings, 0, height, public(20 + height), 100_000)],
        );
        full = reference(&settings, &full, &packet);
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    assert_eq!(node.activate(fork).unwrap(), fork);
    assert!(node.active().unwrap().1 > generation);
    assert_reference(&node, fork, &full);
    assert_reference(&node, second_id, &second_state);
    assert_eq!(node.growth_account(fork, public(10)).unwrap(), None);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 4);
    // Actual reward maturity is part of the same native witness path.
    for _ in 4..=21 {
        let packet = make(&node, fork, vec![]);
        full = reference(&settings, &full, &packet);
        fork = admit(&mut node, &packet);
    }
    assert_reference(&node, fork, &full);
    let current = node.growth_current_working().unwrap();
    assert_eq!(
        (current.block, current.generation),
        (fork, node.active().unwrap().1)
    );
    assert_eq!(current.height, 21);
    assert_eq!(
        current.commitment.working_root,
        pon_executor::root(&current.working).unwrap()
    );
    let before = rows(&node.db);
    let active = node.active().unwrap();
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(rows(&node.db), before);
    assert_reference(&node, fork, &full);
    assert_reference(&node, second_id, &second_state);
}

#[test]
fn native_growth_v2_real_task_escrow_settlement_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &1u64.to_le_bytes(),
            &public(1),
            &12_345u64.to_le_bytes(),
            &6u64.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(12_345u64.to_le_bytes());
    payload.extend(6u64.to_le_bytes());
    let first = make(
        &node,
        settings.genesis(),
        vec![signed(&settings, 0, 1, 2, payload)],
    );
    let first_id = admit(&mut node, &first);
    let row = format!("task:{}", hex::encode(task));
    assert_eq!(
        node.growth_working(first_id).unwrap()[&row]["remaining"],
        12_345
    );
    assert_eq!(
        node.growth_observe(first_id)
            .unwrap()
            .commitment
            .escrow_balance,
        12_345
    );
    let output = [71u8; 32];
    let mut receipt = task.to_vec();
    receipt.extend(output);
    let before = node
        .growth_account(first_id, public(1))
        .unwrap()
        .unwrap()
        .balance;
    let second = make(
        &node,
        first_id,
        vec![
            signed(&settings, 1, 1, 4, receipt.clone()),
            signed(&settings, 0, 2, 5, receipt),
        ],
    );
    let state = reference(
        &settings,
        &reference(&settings, &settings.initial, &first),
        &second,
    );
    let second_id = admit(&mut node, &second);
    assert_reference(&node, second_id, &state);
    assert_eq!(
        node.growth_observe(second_id)
            .unwrap()
            .commitment
            .escrow_balance,
        0
    );
    assert!(
        node.growth_account(second_id, public(1))
            .unwrap()
            .unwrap()
            .balance
            > before
    );
    // Fork retains the pending obligation and expires it through mandatory work.
    let mut fork = first_id;
    for _ in 2..=6 {
        let packet = make(&node, fork, vec![]);
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    node.activate(fork).unwrap();
    assert_eq!(
        node.growth_observe(fork).unwrap().commitment.escrow_balance,
        0
    );
    assert_eq!(
        node.growth_working(fork).unwrap()[&row]["status"],
        "expired"
    );
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(
        node.growth_working(first_id).unwrap()[&row]["remaining"],
        12_345
    );
    assert_eq!(
        node.growth_working(second_id).unwrap()[&row]["status"],
        "settled"
    );
    assert_eq!(
        node.growth_working(fork).unwrap()[&row]["status"],
        "expired"
    );
}

#[test]
fn native_growth_v2_cancelled_writes_and_activation_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(10), 1_000)],
    );
    let before = rows(&node.db);
    for cut in [
        GrowthProgress::BeforePersistence,
        GrowthProgress::AccountNode,
        GrowthProgress::BeforeCommit,
    ] {
        let calls = AtomicUsize::new(0);
        let error = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                if point == cut {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(rows(&node.db), before);
    }
    let id = node.admit_growth(&packet, 100_000).unwrap();
    let admitted = rows(&node.db);
    assert!(node
        .growth_activate_with_progress(id, &|point| if point == GrowthProgress::BeforeCommit {
            Err(Error::new(ErrorCode::PublicRequestCancelled))
        } else {
            Ok(())
        })
        .unwrap_err()
        .is(ErrorCode::PublicRequestCancelled));
    assert_eq!(rows(&node.db), admitted);
    // Cold restart recovers the already committed highest-work block; it never
    // recovers any partial account path or partial activation journal.
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 2);
}

#[test]
fn native_growth_v2_missing_proof_extra_proof_and_external_loss_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let genesis = settings.genesis();
    let packet = make(
        &node,
        genesis,
        vec![transfer(&settings, 0, 1, public(10), 1_000)],
    );
    let parent = node.growth_parent(genesis).unwrap();
    let mut missing = packet.clone();
    missing.accounts = node
        .growth_account_multiproof(genesis, &[public(0), public(3)])
        .unwrap()
        .1;
    assert!(execute(&settings, &parent, &missing, &|_| Ok(())).is_err());
    reseal(&mut missing);
    assert!(node.admit_growth(&missing, 100_000).is_err());
    let mut extra = packet.clone();
    extra.accounts = node
        .growth_account_multiproof(genesis, &[public(0), public(3), public(10), public(99)])
        .unwrap()
        .1;
    assert!(execute(&settings, &parent, &extra, &|_| Ok(())).is_err());
    reseal(&mut extra);
    assert!(node.admit_growth(&extra, 100_000).is_err());
    let mut forged = packet.encode().unwrap();
    forged[4 + trnm_protocol::pon_growth::GROWTH_HEADER_BYTES - 1] ^= 1;
    assert!(GrowthPacket::decode(&forged).is_err());
    let external = Connection::open(dir.path().join("native.sqlite")).unwrap();
    let root = parent.source.stored.accounts.node.unwrap();
    let data: Vec<u8> = external
        .query_row(
            "SELECT data FROM archive_nodes WHERE id=?",
            [root.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    external
        .execute("DELETE FROM archive_nodes WHERE id=?", [root.as_slice()])
        .unwrap();
    assert!(node
        .growth_account(genesis, public(0))
        .unwrap_err()
        .requires_owner_stop());
    drop(node);
    assert!(Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).is_err());
    external
        .execute(
            "INSERT INTO archive_nodes VALUES(?,?)",
            params![root.as_slice(), data],
        )
        .unwrap();
    drop(external);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.next_nonce(public(0)).unwrap(), 1);
}

#[test]
#[ignore = "explicit release gate: actual signed native transition across 65,536 accounts, full work and cold replay"]
fn native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen() {
    let mut source = base_settings();
    source.initial.insert(
        format!("account:{}", hex::encode(public(999))),
        json!({"balance":0,"nonce":7}),
    );
    let mut index = 0u64;
    let mut count = source
        .initial
        .keys()
        .filter(|k| k.starts_with("account:"))
        .count();
    while count < 65_520 {
        let owner = hash(b"growth-dormant-fixture-v2", &[&index.to_le_bytes()]);
        source.initial.insert(
            format!("account:{}", hex::encode(owner)),
            json!({"balance":0,"nonce":7}),
        );
        index += 1;
        count += 1;
    }
    let settings = source
        .with_permanent_account_growth_v2("native-growth-cross-65536")
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let genesis = settings.genesis();
    assert_eq!(
        node.growth_observe(genesis).unwrap().permanent_accounts,
        65_520
    );
    let before: u64 = node
        .db
        .query_row("SELECT count(*) FROM archive_nodes", [], |r| r.get(0))
        .unwrap();
    let mut txs: Vec<_> = (0..32)
        .map(|n| transfer(&settings, 0, n + 1, public(40_000 + n), 100_000))
        .collect();
    txs.push(transfer(&settings, 0, 33, public(999), 200_000));
    let packet = make(&node, genesis, txs);
    assert_eq!(packet.accounts.accounts.len(), 35);
    let full = reference(&settings, &settings.initial, &packet);
    let first = admit(&mut node, &packet);
    let observation = node.growth_observe(first).unwrap();
    assert_eq!(observation.permanent_accounts, 65_552);
    assert_eq!(
        observation.commitment,
        *growth_commitment_from_complete_state_v2(&settings, &full)
            .unwrap()
            .observation()
    );
    let after: u64 = node
        .db
        .query_row("SELECT count(*) FROM archive_nodes", [], |r| r.get(0))
        .unwrap();
    assert!(
        after - before < 4096,
        "writes must copy touched paths, not the whole account tree"
    );
    let owners = [public(0), public(999), public(40_000), public(777)];
    let (_, proof, reads) = node.growth_account_multiproof(first, &owners).unwrap();
    assert_eq!(reads.expanded_witnesses_allocated, 0);
    assert!(reads.archive_point_reads < 1024);
    assert!(proof.encoded_len().unwrap() < 64_000);
    assert!(observation.working_keys < 128);
    // Empty the dormant account with an actual signed nonce-8 transaction. Its
    // zero balance, nonce and existence remain committed and replay is refused.
    let zero = transfer(&settings, 999, 8, public(0), 0);
    let fee = settings.app.fees[1] + zero.len() as u64 * settings.limit("byte_fee_units").unwrap();
    let spend = transfer(&settings, 999, 8, public(0), 200_000 - fee);
    let second_packet = make(&node, first, vec![spend.clone()]);
    let second = admit(&mut node, &second_packet);
    assert_eq!(
        node.growth_account(second, public(999)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 8
        })
    );
    assert!(node
        .make_growth_consensus_maintenance(second, vec![spend], public(3), 31, 4096)
        .is_err());
    let state = node.growth_observe(second).unwrap().commitment;
    let active = node.active().unwrap();
    drop(node);
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(node.growth_observe(second).unwrap().commitment, state);
    assert_eq!(
        node.growth_account(second, public(999)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 8
        })
    );
    assert_eq!(
        node.growth_account(genesis, public(999)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 7
        })
    );
    // Reorg selects an independent heavier branch while both account histories
    // remain queryable; zero-balance nonce never becomes authenticated absence.
    let mut fork = genesis;
    for _ in 1..=3 {
        let candidate = make(&node, fork, vec![]);
        fork = node.admit_growth(&candidate, 100_000).unwrap();
    }
    node.activate(fork).unwrap();
    assert_eq!(
        node.growth_observe(fork).unwrap().permanent_accounts,
        65_520
    );
    assert_eq!(
        node.growth_account(fork, public(999)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 7
        })
    );
    assert_eq!(
        node.growth_account(second, public(999)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 8
        })
    );
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, fork);
    let evidence = json!({"schema":"native-growth-scale-observation-v2", "genesis_accounts":65_520,
        "grown_accounts":65_552,"grown_block":hex::encode(first),"zero_balance_block":hex::encode(second),
        "active_fork":hex::encode(fork),"working_keys":observation.working_keys,"copied_nodes":after-before,
        "point_reads":reads.archive_point_reads,"witness_bytes":proof.encoded_len().unwrap(),
        "signed_transfers":34,"cold_reopens":2,"reorgs":1,"expanded_witnesses_allocated":0,
        "zero_balance_nonce":8,"nonce_before_funding":7,"full_reference_commitment":observation.commitment,
        "preallocated_genesis_is_not_historical_growth":true,"throughput_claim":false});
    export_scale_evidence(&node, &evidence);
    eprintln!("native_growth_v2 evidence: {evidence}");
}

#[test]
fn native_growth_v2_real_disk_full_rolls_back_all_native_rows() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        (0..64)
            .map(|n| transfer(&settings, 0, n + 1, public(10_000 + n), 1_000))
            .collect(),
    );
    let before = rows(&node.db);
    let pages: u64 = node
        .db
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    node.db
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let error = node.admit_growth(&packet, 100_000).unwrap_err();
    assert!(
        error.to_string().to_ascii_lowercase().contains("full"),
        "actual SQLite full refusal: {error}"
    );
    assert_eq!(rows(&node.db), before);
    node.db
        .pragma_update(None, "max_page_count", pages + 1024)
        .unwrap();
    let id = admit(&mut node, &packet);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 65);
}

#[test]
fn native_growth_v2_process_cut_before_commit_recovers() {
    const CHILD: &str = "TRNM_GROWTH_V2_PROCESS_CUT_DIR";
    if let Some(path) = std::env::var_os(CHILD) {
        let settings = settings();
        let mut node =
            Node::open_with_permanent_account_growth_v2(Path::new(&path), settings.clone())
                .unwrap();
        let packet = make(
            &node,
            settings.genesis(),
            vec![transfer(&settings, 0, 1, public(10), 1_000)],
        );
        node.admit_growth_with_progress(&packet, 100_000, &|point| {
            if point == GrowthProgress::BeforeCommit {
                std::process::exit(91);
            }
            Ok(())
        })
        .unwrap();
        panic!("process cut did not execute");
    }
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let before = rows(&node.db);
    drop(node);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("native_growth_v2_process_cut_before_commit_recovers")
        .arg("--nocapture")
        .env(CHILD, dir.path())
        .status()
        .unwrap();
    assert_eq!(child.code(), Some(91));
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    assert_eq!(rows(&node.db), before);
    assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
    assert_eq!(
        node.growth_account(settings.genesis(), public(10)).unwrap(),
        None
    );
    assert_eq!(node.next_nonce(public(0)).unwrap(), 1);
}

fn export_scale_evidence(node: &Node, observation: &serde_json::Value) {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
    };
    let Some(directory) = std::env::var_os("TRNM_NATIVE_GROWTH_V2_EXPORT_DIR") else {
        return;
    };
    let directory = Path::new(&directory);
    // Atomic create-only root, including rejection of a dangling symlink. An
    // existing failed or successful run is never overwritten by a later run.
    fs::create_dir(directory).unwrap();
    fn write(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn file_hash(path: &Path) -> String {
        let mut file = std::fs::File::open(path).unwrap();
        let mut hash = Sha256::new();
        let mut chunk = [0u8; 65_536];
        loop {
            let count = file.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            hash.update(&chunk[..count]);
        }
        hex::encode(hash.finalize())
    }
    node.growth_guard().unwrap();
    let active = node.active().unwrap();
    let settings = &node.settings;
    let settings_value = json!({"schema":"native-growth-explicit-genesis-input-v2",
        "fixture":{"source":"development_with_profiles","genesis_timestamp":1,
            "evaluation_profile":"native-public-evaluation-dev-v1","task_profile":continuity_v1::PROFILE,
            "namespace":"native-growth-cross-65536","dormant_domain":"growth-dormant-fixture-v2",
            "initial_accounts":65_520,"dormant_nonce":7,"special_dormant_development_key_index":999},
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"params":settings.app.params,
        "initial":settings.initial});
    write(
        &directory.join("settings.json"),
        &serde_json::to_vec(&settings_value).unwrap(),
    );
    let blocks = directory.join("packets");
    fs::create_dir(&blocks).unwrap();
    let ids: Vec<Hash> = node
        .db
        .prepare("SELECT id FROM blocks WHERE height>0 ORDER BY height,id")
        .unwrap()
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| bytes32(r.unwrap()).unwrap())
        .collect();
    let mut packets = Vec::new();
    for id in ids {
        let packet = node.growth_packet(id).unwrap();
        let bytes = packet.encode().unwrap();
        let name = format!("{}.pnp2", hex::encode(id));
        write(&blocks.join(&name), &bytes);
        packets.push(json!({"block":hex::encode(id),"path":format!("packets/{name}"),
            "bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),"height":packet.header.ledger.height,
            "parent":hex::encode(packet.header.ledger.parent)}));
    }
    fs::File::open(&blocks).unwrap().sync_all().unwrap();
    node.db
        .execute(
            "VACUUM INTO ?",
            [directory.join("native.sqlite").to_str().unwrap()],
        )
        .unwrap();
    fs::File::open(directory.join("native.sqlite"))
        .unwrap()
        .sync_all()
        .unwrap();
    node.growth_guard().unwrap();
    assert_eq!(node.active().unwrap(), active);
    let head = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(head.status.success());
    // Hash bytes embedded into this test binary at compilation. This is the
    // relevant-source manifest, not a claim that a dirty checkout is a commit.
    let embedded = [
        ("pon-node/store.rs", include_str!("../../store.rs")),
        ("pon-node/store/growth.rs", include_str!("../growth.rs")),
        ("pon-node/store/growth/packet.rs", include_str!("packet.rs")),
        (
            "pon-node/store/growth/profile.rs",
            include_str!("profile.rs"),
        ),
        (
            "pon-node/store/growth/recovery.rs",
            include_str!("recovery.rs"),
        ),
        ("pon-node/store/growth/tests.rs", include_str!("tests.rs")),
        (
            "pon-node/state_witness.rs",
            include_str!("../../account_archive_execution/state_witness.rs"),
        ),
        (
            "pon-node/state_witness/native_growth.rs",
            include_str!("../../account_archive_execution/state_witness/native_growth.rs"),
        ),
        (
            "pon-node/native_store.rs",
            include_str!("../../account_archive_prototype/native_store.rs"),
        ),
        (
            "mvcc/pon_executor.rs",
            include_str!("../../../../trnm-mvcc-fee/src/pon_executor.rs"),
        ),
        (
            "mvcc/growth.rs",
            include_str!("../../../../trnm-mvcc-fee/src/pon_executor/growth.rs"),
        ),
        (
            "mvcc/continuity_v1.rs",
            include_str!("../../../../trnm-mvcc-fee/src/continuity_v1.rs"),
        ),
        (
            "protocol/pon_growth.rs",
            include_str!("../../../../trnm-protocol/src/pon_growth.rs"),
        ),
    ];
    let sources: BTreeMap<_, _> = embedded
        .into_iter()
        .map(|(path, text)| (path, hex::encode(Sha256::digest(text.as_bytes()))))
        .collect();
    let manifest = json!({"schema":"native-growth-reproducible-evidence-v2","observation":observation,
        "active":{"block":hex::encode(active.0),"generation":active.1},"packets":packets,
        "database":{"path":"native.sqlite","sha256":file_hash(&directory.join("native.sqlite"))},
        "settings":{"path":"settings.json","sha256":file_hash(&directory.join("settings.json"))},
        "source":{"observed_git_head":String::from_utf8(head.stdout).unwrap().trim(),
            "embedded_relevant_source_sha256":sources,"test_binary_sha256":file_hash(&std::env::current_exe().unwrap()),
            "scope":"exact embedded relevant sources and test binary; git HEAD alone does not identify dirty source"},
        "production_acceptance":false});
    write(
        &directory.join("native.json"),
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );
    fs::File::open(directory).unwrap().sync_all().unwrap();
}
