//! Actual native admission tests. The large fixture explicitly preallocates
//! dormant zero-balance genesis accounts below the old limit; only signed,
//! fully proved successor transactions cross it. It is not synthetic history.
use super::*;
use crate::{development_public, ErrorCode, Packet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

// The pre-change collect algorithm remains a test-only differential oracle.
// Counters observe its actual retained vectors, not another streaming model.
fn collected_cold_journal(node: &Node) -> Result<(usize, usize)> {
    let values: Vec<(u64, u64, u64, Vec<u8>)> = node
        .db
        .prepare("SELECT generation,ordinal,kind,block FROM events ORDER BY generation,ordinal")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let count = values.len();
    let mut peak = 0;
    let mut tip = node.settings.genesis();
    let mut generation = 0u64;
    let mut old = tip;
    let mut changes = Vec::new();
    for (g, ordinal, kind, raw) in values {
        if g != generation {
            ensure(g == generation + 1, "GROWTH_REORG_JOURNAL")?;
            generation = g;
            old = tip;
            changes.clear();
        }
        ensure(ordinal == changes.len() as u64, "GROWTH_REORG_JOURNAL")?;
        let id = bytes32(raw)?;
        match kind {
            0 => {
                ensure(tip == id, "GROWTH_REORG_JOURNAL")?;
                tip = node.record(id)?.parent.ok_or("GROWTH_REORG_JOURNAL")?;
            }
            1 => {
                ensure(node.record(id)?.parent == Some(tip), "GROWTH_REORG_JOURNAL")?;
                tip = id;
            }
            _ => return Err("GROWTH_REORG_JOURNAL".into()),
        }
        changes.push((kind, id));
        peak = peak.max(changes.len());
    }
    ensure(
        node.active()? == (tip, generation) && node.slot()? == generation,
        "GROWTH_REORG_JOURNAL",
    )?;
    if generation > 0 {
        node.growth_check_latest_journal(old, tip, generation, &changes)?;
    } else {
        let rows: u64 = node.db.query_row(
            "SELECT (SELECT count(*) FROM reorg)+(SELECT count(*) FROM steps)",
            [],
            |r| r.get(0),
        )?;
        ensure(rows == 0, "GROWTH_REORG_JOURNAL")?;
    }
    Ok((count, peak))
}

fn cold_journal_error(error: &Error) -> String {
    use std::error::Error as _;
    format!(
        "{}|{:?}|{:?}|{}|{:?}",
        error,
        error.code(),
        error.kind(),
        error.requires_owner_stop(),
        error
            .source()
            .and_then(|source| source.downcast_ref::<rusqlite::Error>())
    )
}

fn compare_cold_journal(node: &Node) -> Result<super::recovery::ColdJournalReads> {
    assert!(
        !node.db.is_autocommit(),
        "original cold read snapshot required"
    );
    let changes = node.db.total_changes();
    let old = collected_cold_journal(node);
    let new = node.growth_check_journal();
    assert_eq!(
        old.as_ref().map(|_| ()).map_err(cold_journal_error),
        new.as_ref().map(|_| ()).map_err(cold_journal_error)
    );
    assert_eq!(node.db.total_changes(), changes);
    new
}

#[test]
fn native_growth_v2_cold_journal_streams_real_history_and_deep_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let mut old = settings.genesis();
    for _ in 0..24 {
        let packet = make(&node, old, vec![]);
        old = admit(&mut node, &packet);
    }
    let tx = node.db.unchecked_transaction().unwrap();
    let observation = compare_cold_journal(&node).unwrap();
    assert_eq!(collected_cold_journal(&node).unwrap(), (24, 1));
    assert_eq!(
        (observation.typed_events, observation.semantic_events),
        (24, 24)
    );
    assert_eq!(observation.peak_event_rows, 2);
    tx.rollback().unwrap();
    let mut fork = settings.genesis();
    for height in 1..=25 {
        let transactions = if height == 1 {
            vec![transfer(&settings, 0, 1, public(100), 1000)]
        } else {
            vec![]
        };
        let packet = make(&node, fork, transactions);
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    assert_eq!(node.growth_activate(fork).unwrap(), fork);
    let before = rows(&node.db);
    let tx = node.db.unchecked_transaction().unwrap();
    let observation = compare_cold_journal(&node).unwrap();
    assert_eq!(collected_cold_journal(&node).unwrap(), (73, 49));
    assert_eq!(
        (observation.typed_events, observation.semantic_events),
        (73, 73)
    );
    assert_eq!(
        (observation.latest_steps, observation.latest_events),
        (49, 49)
    );
    assert_eq!(observation.peak_event_rows, 2);
    eprintln!("growth_cold_journal_actual_rows old_vectors=(73,49) new={observation:?}; excludes SQLite pages/RSS/other cold audit collections");
    tx.rollback().unwrap();
    let faults = [
        "UPDATE events SET generation=0 WHERE generation=1",
        "UPDATE events SET generation=100 WHERE generation=25",
        "UPDATE events SET ordinal=1 WHERE generation=1",
        "DELETE FROM events WHERE generation=1",
        "UPDATE events SET kind=7 WHERE generation=1",
        "UPDATE events SET block=zeroblob(31) WHERE generation=1",
        "UPDATE events SET block='typed-text' WHERE generation=25 AND ordinal=48",
        "UPDATE events SET kind='typed-kind' WHERE generation=25 AND ordinal=48",
        "UPDATE events SET ordinal='typed-ordinal' WHERE generation=25 AND ordinal=48",
        "INSERT INTO events SELECT generation,99,kind,block FROM events WHERE generation=25 AND ordinal=48",
        "DELETE FROM steps WHERE ordinal=0",
        "UPDATE steps SET ordinal=ordinal+1000",
        "INSERT INTO steps SELECT 999,kind,block FROM steps WHERE ordinal=0",
        "UPDATE steps SET block=zeroblob(100000) WHERE ordinal=48",
        "UPDATE steps SET kind='typed-step' WHERE ordinal=48",
        "UPDATE reorg SET old_tip=zeroblob(32)",
        "UPDATE reorg SET new_tip=zeroblob(32)",
        "UPDATE reorg SET generation=100",
        "UPDATE reorg SET cursor=0",
        "UPDATE reorg SET done=0",
        "UPDATE reorg SET old_tip='typed-reorg'",
        "UPDATE active SET tip=zeroblob(32)",
        "UPDATE active SET state_slot=state_slot+1",
        // Collect converted every row first: late type errors must still win.
        "UPDATE events SET kind=7 WHERE generation=1; UPDATE events SET block='late-type' WHERE generation=25 AND ordinal=48",
        "UPDATE events SET block=zeroblob(31) WHERE generation=1; UPDATE events SET kind='late-kind' WHERE generation=25 AND ordinal=48",
        // An oversized BLOB is a later shape failure, not a premature type error.
        "UPDATE events SET kind=7 WHERE generation=1; UPDATE events SET block=zeroblob(100000) WHERE generation=25 AND ordinal=48",
        "UPDATE events SET kind=7 WHERE generation=1; UPDATE steps SET kind='later-step-type' WHERE ordinal=48",
    ];
    for (index, sql) in faults.into_iter().enumerate() {
        let tx = node.db.unchecked_transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        let error = compare_cold_journal(&node).unwrap_err();
        if index == 23 || index == 24 {
            use std::error::Error as _;
            assert!(
                error.source().unwrap().is::<rusqlite::Error>(),
                "{index}: {error:?}"
            );
        }
        tx.rollback().unwrap();
        assert_eq!(rows(&node.db), before, "fault {index}");
    }
    let active = node.active().unwrap();
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(rows(&node.db), before);
}

#[test]
fn native_growth_v2_cold_journal_zero_generation_and_late_typed_error_priority() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let tx = node.db.unchecked_transaction().unwrap();
    assert_eq!(compare_cold_journal(&node).unwrap().peak_event_rows, 0);
    tx.rollback().unwrap();
    for sql in [
        "INSERT INTO steps VALUES(0,1,zeroblob(32))",
        "INSERT INTO reorg VALUES(1,zeroblob(32),zeroblob(32),0,0,1)",
    ] {
        let tx = node.db.unchecked_transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        assert_eq!(
            compare_cold_journal(&node).unwrap_err().to_string(),
            "GROWTH_REORG_JOURNAL"
        );
        tx.rollback().unwrap();
    }
    let tx = node.db.unchecked_transaction().unwrap();
    tx.execute(
        "INSERT INTO events VALUES(1,0,7,?)",
        [settings.genesis().as_slice()],
    )
    .unwrap();
    tx.execute_batch("INSERT INTO events VALUES(2,0,1,'later-invalid-type')")
        .unwrap();
    let error = compare_cold_journal(&node).unwrap_err();
    use std::error::Error as _;
    assert!(error.source().unwrap().is::<rusqlite::Error>());
    tx.rollback().unwrap();
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
fn native_growth_v2_exact_packet_observation_binds_bytes_context_and_active_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(9), 1000)],
    );
    let initial = rows(&node.db);
    let absent = node.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(absent["stored_exact"], false);
    assert_eq!(absent["active_chain_member"], false);
    assert!(absent["block_height"].is_null());
    assert!(absent["accepted_task"].is_null());
    assert_eq!(rows(&node.db), initial);

    let id = admit(&mut node, &packet);
    let retained = rows(&node.db);
    let changes = node.db.total_changes();
    let exact = node.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(
        exact["schema"],
        "pon-native-exact-growth-packet-observation-v1"
    );
    assert_eq!(exact["packet_profile"], "PNP2");
    assert_eq!(exact["state_profile"], limits::PROFILE);
    assert_eq!(exact["network"], hex::encode(settings.network()));
    assert_eq!(exact["parameters"], hex::encode(settings.parameters()));
    assert_eq!(exact["genesis"], hex::encode(settings.genesis()));
    assert_eq!(exact["block"], hex::encode(id));
    assert_eq!(exact["stored_exact"], true);
    assert_eq!(exact["active_chain_member"], true);
    assert_eq!(exact["active_depth"], 0);
    assert_eq!(exact["active_work_depth_hex"], hex::encode([0u8; 64]));
    assert_eq!(exact["generation"], node.active().unwrap().1);
    assert!(exact["accepted_task"].is_null());
    assert_eq!(exact["local_target_only"], true);
    for key in [
        "global_absence_authority",
        "confirmation_authority",
        "finality_authority",
        "execution_authority",
        "production_activation",
    ] {
        assert_eq!(exact[key], false);
    }
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(rows(&node.db), retained);

    // PNP2 identity includes the trace, not every W1 byte. An unchanged ID
    // cannot make changed proof bytes count as the exact retained packet.
    let mut changed = packet.clone();
    changed.proof[0] ^= 1;
    assert_eq!(changed.id().unwrap(), id);
    assert_eq!(
        node.growth_exact_packet_observation(&changed)
            .unwrap_err()
            .to_string(),
        "DUPLICATE_CONTENT"
    );
    let mut foreign = packet.clone();
    foreign.header.ledger.network[0] ^= 1;
    assert_eq!(
        node.growth_exact_packet_observation(&foreign)
            .unwrap_err()
            .to_string(),
        "NETWORK"
    );
    assert_eq!(rows(&node.db), retained);

    let child = make(&node, id, vec![]);
    let child_id = admit(&mut node, &child);
    let deeper = node.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(deeper["active_depth"], 1);
    assert_eq!(
        deeper["active_work_depth_hex"],
        hex::encode(
            consensus::required_work(child.header.ledger.target)
                .unwrap()
                .bytes()
        )
    );
    assert_eq!(deeper["active_membership_sql_lookups"], 3);
    let tx = node.db.unchecked_transaction().unwrap();
    assert_eq!(
        node.growth_active_member(child_id, id, 1, 1, &|_| Ok(()))
            .unwrap_err()
            .to_string(),
        "GROWTH_MEMBERSHIP_BUDGET"
    );
    tx.rollback().unwrap();

    let mut fork = settings.genesis();
    for _ in 0..3 {
        let next = make(&node, fork, vec![]);
        fork = node.admit_growth(&next, 100_000).unwrap();
    }
    assert_eq!(node.activate(fork).unwrap(), fork);
    let before = rows(&node.db);
    let inactive = node.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(inactive["stored_exact"], true);
    assert_eq!(inactive["active_chain_member"], false);
    assert!(inactive["active_depth"].is_null());
    assert!(inactive["active_work_depth_hex"].is_null());
    assert!(inactive["accepted_task"].is_null());
    assert_ne!(inactive["generation"], exact["generation"]);
    assert_eq!(rows(&node.db), before);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(
        node.growth_exact_packet_observation(&packet).unwrap(),
        inactive
    );
    assert_eq!(rows(&node.db), before);
}

#[test]
fn native_growth_v2_packet_observer_opens_read_only_without_recovering() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let missing = dir.path().join("missing");
    assert!(Node::open_growth_packet_observer(&missing, settings.clone()).is_err());
    assert!(!missing.exists());
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(&node, settings.genesis(), vec![]);
    // Admission can survive a lost acknowledgement before activation. A status
    // read must report the actual old selection, not finish the owner's write.
    let id = node.admit_growth(&packet, 100_000).unwrap();
    assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
    let before = rows(&node.db);
    drop(node);
    let observer = Node::open_growth_packet_observer(dir.path(), settings.clone()).unwrap();
    assert_eq!(observer.active().unwrap(), (settings.genesis(), 0));
    let result = observer.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(result["stored_exact"], true);
    assert_eq!(result["active_chain_member"], false);
    assert_eq!(result["generation"], 0);
    assert_eq!(observer.db.total_changes(), 0);
    assert!(observer
        .db
        .execute("UPDATE active SET generation=generation", [])
        .is_err());
    assert_eq!(rows(&observer.db), before);
    drop(observer);

    // The ordinary writer retains its original recovery behavior.
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    assert_eq!(node.active().unwrap(), (id, 1));
    node.db.execute("UPDATE reorg SET done=0", []).unwrap();
    let pending = rows(&node.db);
    drop(node);
    let error = match Node::open_growth_packet_observer(dir.path(), settings) {
        Ok(_) => panic!("incomplete reorg must remain unavailable to the observer"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "GROWTH_REORG_JOURNAL");
    let database = Connection::open(dir.path().join("native.sqlite")).unwrap();
    assert_eq!(rows(&database), pending);
}

// Include every byte of these deliberately small real Node fixtures. SQL row
// counts alone cannot detect SQLite creating or changing WAL/SHM sidecars.
fn cold_observer_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn native_growth_v2_cold_observer_preserves_closed_wal_namespace() {
    use fs2::FileExt;
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut writer =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let packet = make(
        &writer,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(100), 1000)],
    );
    let id = admit(&mut writer, &packet);
    let expected = writer.growth_exact_packet_observation(&packet).unwrap();
    let account = writer.growth_account(id, public(100)).unwrap().unwrap();
    drop(writer);
    let before = cold_observer_files(directory.path());
    assert_eq!(before["native.sqlite"][18..20], [2, 2]);
    assert!(!before.contains_key("native.sqlite-wal"));
    assert!(!before.contains_key("native.sqlite-shm"));
    let observer = Node::open_growth_packet_observer(directory.path(), settings.clone()).unwrap();
    assert_eq!(
        observer.growth_exact_packet_observation(&packet).unwrap(),
        expected
    );
    assert_eq!(
        observer.growth_account(id, public(100)).unwrap().as_ref(),
        Some(&account)
    );
    assert_eq!(observer.db.total_changes(), 0);
    assert!(observer
        .db
        .execute("UPDATE active SET generation=generation", [])
        .is_err());
    let competing_owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("owner.lock"))
        .unwrap();
    assert!(competing_owner.try_lock_exclusive().is_err());
    assert_eq!(
        cold_observer_files(directory.path()),
        before,
        "a cold observer must not create or change source WAL/SHM files"
    );
    drop(observer);
    assert_eq!(cold_observer_files(directory.path()), before);
    competing_owner.try_lock_exclusive().unwrap();
    FileExt::unlock(&competing_owner).unwrap();
}

#[test]
fn native_growth_v2_cold_observer_requires_existing_owner_without_creating_it() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    drop(Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap());
    std::fs::remove_file(directory.path().join("owner.lock")).unwrap();
    let before = cold_observer_files(directory.path());
    let result = Node::open_growth_packet_observer(directory.path(), settings);
    assert_eq!(cold_observer_files(directory.path()), before);
    assert!(
        result.is_err(),
        "missing source ownership cannot be manufactured by observation"
    );
}

#[test]
fn native_growth_v2_cold_observer_refuses_live_logs_before_sqlite_or_packet_absence() {
    let original = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut writer =
        Node::open_with_permanent_account_growth_v2(original.path(), settings.clone()).unwrap();
    writer
        .db
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let packet = make(
        &writer,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(100), 1000)],
    );
    let id = admit(&mut writer, &packet);
    let expected = writer.growth_exact_packet_observation(&packet).unwrap();
    let account = writer.growth_account(id, public(100)).unwrap().unwrap();
    // Copy a quiescent, genuinely committed Node main/WAL pair while its one
    // writer remains open. The copied namespace has no process holding its
    // owner lock, as after a crash; the original writer is never disturbed.
    let directory = tempfile::tempdir().unwrap();
    for name in [
        "native.sqlite",
        "native.sqlite-wal",
        "native.sqlite-shm",
        "owner.lock",
    ] {
        std::fs::copy(original.path().join(name), directory.path().join(name)).unwrap();
    }
    let before = cold_observer_files(directory.path());
    assert!(before["native.sqlite-wal"].len() > 32);
    let result = Node::open_growth_packet_observer(directory.path(), settings.clone());
    assert_eq!(cold_observer_files(directory.path()), before);
    let error = match result {
        Ok(_) => {
            panic!("existing logs require ordinary writer recovery, never a packet-status answer")
        }
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "GROWTH_OBSERVATION_RECOVERY_REQUIRED");
    let recovered =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    assert_eq!(
        recovered.growth_exact_packet_observation(&packet).unwrap(),
        expected
    );
    assert_eq!(
        recovered.growth_account(id, public(100)).unwrap().as_ref(),
        Some(&account)
    );
    drop(recovered);
    let closed = cold_observer_files(directory.path());
    assert!(!closed.contains_key("native.sqlite-wal"));
    assert!(!closed.contains_key("native.sqlite-shm"));
    let observer = Node::open_growth_packet_observer(directory.path(), settings).unwrap();
    assert_eq!(
        observer.growth_exact_packet_observation(&packet).unwrap(),
        expected
    );
    assert_eq!(
        observer.growth_account(id, public(100)).unwrap().as_ref(),
        Some(&account)
    );
    drop(observer);
    assert_eq!(cold_observer_files(directory.path()), closed);
}

#[test]
fn native_growth_v2_cold_observer_bounds_copy_and_cleans_private_snapshot() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    drop(Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap());
    let before = cold_observer_files(directory.path());
    let bytes = before["native.sqlite"].len() as u64;
    let error = match Node::open_growth_packet_observer_with_snapshot_byte_limit(
        directory.path(),
        settings.clone(),
        bytes - 1,
    ) {
        Ok(_) => panic!("a main file above the local copy budget must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "GROWTH_OBSERVATION_SNAPSHOT_LIMIT");
    assert_eq!(cold_observer_files(directory.path()), before);
    let observer = Node::open_growth_packet_observer_with_snapshot_byte_limit(
        directory.path(),
        settings,
        bytes,
    )
    .unwrap();
    let snapshot = observer.directory.clone();
    assert_ne!(snapshot, directory.path());
    assert_eq!(
        std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    for name in ["native.sqlite", "owner.lock"] {
        assert_eq!(
            std::fs::metadata(snapshot.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
    assert_eq!(cold_observer_files(directory.path()), before);
    drop(observer);
    assert!(
        !snapshot.exists(),
        "close SQLite before removing its private namespace"
    );
    assert_eq!(cold_observer_files(directory.path()), before);
}

#[test]
fn native_growth_v2_cold_observer_fences_source_changes_despite_private_epoch() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut writer =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let packet = make(&writer, settings.genesis(), vec![]);
    admit(&mut writer, &packet);
    drop(writer);
    let observer = Node::open_growth_packet_observer(directory.path(), settings).unwrap();
    let version: u64 = observer
        .db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap();
    let mut changed = std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("native.sqlite"))
        .unwrap();
    changed.write_all(&[0]).unwrap();
    let before = cold_observer_files(directory.path());
    assert_eq!(
        observer
            .db
            .query_row("PRAGMA data_version", [], |row| row.get::<_, u64>(0))
            .unwrap(),
        version,
    );
    assert_eq!(
        observer
            .growth_exact_packet_observation(&packet)
            .unwrap_err()
            .to_string(),
        "GROWTH_OBSERVATION_FILE_CHANGED",
    );
    assert_eq!(cold_observer_files(directory.path()), before);
}

#[test]
fn native_growth_v2_exact_packet_observation_refuses_foreign_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(&node, settings.genesis(), vec![]);
    admit(&mut node, &packet);
    let foreign = Connection::open(dir.path().join("native.sqlite")).unwrap();
    foreign
        .execute("UPDATE active SET generation=generation+1", [])
        .unwrap();
    assert_eq!(
        node.growth_exact_packet_observation(&packet)
            .unwrap_err()
            .to_string(),
        "GROWTH_STORAGE_EPOCH_CHANGED"
    );
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
    let exact = node.growth_exact_packet_observation(&second).unwrap();
    assert_eq!(exact["accepted_task"]["task_id"], hex::encode(task));
    assert_eq!(exact["accepted_task"]["owner"], hex::encode(public(0)));
    assert_eq!(exact["accepted_task"]["provider"], hex::encode(public(1)));
    assert_eq!(exact["accepted_task"]["output_sha256"], hex::encode(output));
    assert_eq!(exact["accepted_task"]["accepted_in_exact_packet"], true);
    assert_eq!(exact["accepted_task"]["current_status"], "settled");
    assert_eq!(
        exact["accepted_task"]["accept_tx_id"],
        hex::encode(
            Envelope::decode(&second.transactions[1])
                .unwrap()
                .id()
                .unwrap()
        )
    );
    assert!(node.growth_exact_packet_observation(&first).unwrap()["accepted_task"].is_null());
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
    let reverted = node.growth_exact_packet_observation(&second).unwrap();
    assert_eq!(reverted["stored_exact"], true);
    assert_eq!(reverted["active_chain_member"], false);
    assert!(reverted["accepted_task"].is_null());
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

#[derive(Clone, Copy, Debug)]
enum ProofTestPhase {
    Parent,
    Commitment,
    FinalSuccessor,
}
impl ProofTestPhase {
    fn point(self, progress: GrowthProgress) -> Option<multiproof::MultiproofProgress> {
        match (self, progress) {
            (Self::Parent, GrowthProgress::ParentProof(point))
            | (Self::Commitment, GrowthProgress::CommitmentProof(point))
            | (Self::FinalSuccessor, GrowthProgress::FinalSuccessorProof(point)) => Some(point),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum ProofTestCut {
    Early,
    Hash,
    Late,
}
impl ProofTestCut {
    fn matches(self, point: multiproof::MultiproofProgress) -> bool {
        use multiproof::MultiproofProgress as Point;
        match self {
            Self::Early => matches!(
                point,
                Point::Account { index: 0 } | Point::Update { index: 0 }
            ),
            Self::Hash => matches!(point, Point::Hash { .. }),
            Self::Late => point == Point::BeforeOutput,
        }
    }
}
#[derive(Debug)]
struct ProofControlSource(std::sync::Arc<()>);
impl std::fmt::Display for ProofControlSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original growth proof control source")
    }
}
impl std::error::Error for ProofControlSource {}

fn cancel_growth_proof_at(phase: ProofTestPhase) {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(80), 1_000)],
    );
    let before = rows(&node.db);
    let active_before = node.active().unwrap();
    for cut in [ProofTestCut::Early, ProofTestCut::Hash, ProofTestCut::Late] {
        for with_source in [false, true] {
            let cut_seen = AtomicBool::new(false);
            let identity = std::sync::Arc::new(());
            let error = node
                .admit_growth_with_progress(&packet, 100_000, &|point| {
                    assert!(
                        !cut_seen.load(Ordering::Relaxed),
                        "progress after failed callback"
                    );
                    if phase.point(point).is_some_and(|point| cut.matches(point)) {
                        cut_seen.store(true, Ordering::Relaxed);
                        if with_source {
                            Err(Error::from(std::io::Error::new(
                                std::io::ErrorKind::Interrupted,
                                ProofControlSource(identity.clone()),
                            )))
                        } else {
                            Err(Error::new(ErrorCode::PublicRequestCancelled))
                        }
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(cut_seen.load(Ordering::Relaxed), "{phase:?} {cut:?}");
            if with_source {
                assert_eq!(error.kind(), crate::ErrorKind::Transport);
                let source = std::error::Error::source(&error)
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<ProofControlSource>()
                    .unwrap();
                assert!(std::sync::Arc::ptr_eq(&identity, &source.0));
            } else {
                assert!(error.is(ErrorCode::PublicRequestCancelled), "{error:?}");
                assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
            }
            assert_eq!(node.active().unwrap(), active_before);
            assert_eq!(rows(&node.db), before, "{phase:?} {cut:?}");
            assert!(node.growth_packet(packet.id().unwrap()).is_err());
        }
    }
    let id = admit(&mut node, &packet);
    let active = node.active().unwrap();
    let after = rows(&node.db);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(
        node.growth_account(id, public(80))
            .unwrap()
            .unwrap()
            .balance,
        1_000
    );
    assert_eq!(rows(&node.db), after);
}

#[test]
fn native_growth_v2_parent_proof_cancellation_preserves_original_error() {
    cancel_growth_proof_at(ProofTestPhase::Parent);
}

#[test]
fn native_growth_v2_commitment_proof_cancellation_preserves_original_error() {
    cancel_growth_proof_at(ProofTestPhase::Commitment);
}

#[test]
fn native_growth_v2_final_successor_proof_cancellation_preserves_original_error() {
    cancel_growth_proof_at(ProofTestPhase::FinalSuccessor);
}

#[test]
fn native_growth_v2_work_replay_cancellation_preserves_original_error() {
    use pon_work::VerificationProgress as Point;
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(81), 1_000)],
    );
    let before = rows(&node.db);
    let active_before = node.active().unwrap();
    for cut in [
        Point::BeforeReplay,
        Point::Noise {
            label: 0,
            counter: 0,
        },
        Point::MatrixRow { row: 0 },
        Point::TranscriptTile {
            row: 0,
            column: 0,
            inner: 0,
        },
        Point::BeforeProduct,
        Point::BeforeVerifiedWork,
    ] {
        for with_source in [false, true] {
            let cut_seen = AtomicBool::new(false);
            let identity = std::sync::Arc::new(());
            let error = node
                .admit_growth_with_progress(&packet, 100_000, &|point| {
                    assert!(
                        !cut_seen.load(Ordering::Relaxed),
                        "progress after failed Work"
                    );
                    if point == GrowthProgress::Work(cut) {
                        cut_seen.store(true, Ordering::Relaxed);
                        if with_source {
                            Err(Error::from(std::io::Error::new(
                                std::io::ErrorKind::Interrupted,
                                ProofControlSource(identity.clone()),
                            )))
                        } else {
                            Err(Error::new(ErrorCode::PublicRequestCancelled))
                        }
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(cut_seen.load(Ordering::Relaxed), "{cut:?}");
            if with_source {
                assert_eq!(error.kind(), crate::ErrorKind::Transport);
                let source = std::error::Error::source(&error)
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<ProofControlSource>()
                    .unwrap();
                assert!(std::sync::Arc::ptr_eq(&identity, &source.0));
            } else {
                assert!(error.is(ErrorCode::PublicRequestCancelled), "{error:?}");
                assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
            }
            assert_eq!(node.active().unwrap(), active_before);
            assert_eq!(rows(&node.db), before, "{cut:?}");
            assert!(node.growth_packet(packet.id().unwrap()).is_err());
        }
    }
    let id = admit(&mut node, &packet);
    let active = node.active().unwrap();
    let after = rows(&node.db);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(
        node.growth_account(id, public(81))
            .unwrap()
            .unwrap()
            .balance,
        1_000
    );
    assert_eq!(rows(&node.db), after);
}

#[test]
fn native_growth_v2_work_failures_never_publish_or_reuse_success() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(82), 1_000)],
    );
    let at = 4 + 2 * pon_work::CELLS * 4;
    let mut field = packet.clone();
    field.proof[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut product = packet.clone();
    let old = u32::from_le_bytes(product.proof[at..at + 4].try_into().unwrap());
    let changed = ((u128::from(old) + 1) % pon_work::Q) as u32;
    product.proof[at..at + 4].copy_from_slice(&changed.to_le_bytes());
    let before = rows(&node.db);
    let active_before = node.active().unwrap();
    for (bad, expected, expected_replay) in [
        (&field, "WORK:Field", false),
        (&product, "WORK:Product", true),
    ] {
        assert_eq!(bad.id().unwrap(), packet.id().unwrap());
        for _ in 0..2 {
            let replay = AtomicBool::new(false);
            let product_started = AtomicBool::new(false);
            let error = node
                .admit_growth_with_progress(bad, 100_000, &|point| {
                    match point {
                        GrowthProgress::BeforeContext
                        | GrowthProgress::HeaderAncestor { .. }
                        | GrowthProgress::BeforeWork => {}
                        GrowthProgress::Work(work) => {
                            replay.store(true, Ordering::Relaxed);
                            if work == pon_work::VerificationProgress::BeforeProduct {
                                product_started.store(true, Ordering::Relaxed);
                            }
                            assert_ne!(work, pon_work::VerificationProgress::BeforeVerifiedWork);
                        }
                        _ => panic!("failed Work reached a later stage: {point:?}"),
                    }
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert_eq!(replay.load(Ordering::Relaxed), expected_replay);
            assert_eq!(product_started.load(Ordering::Relaxed), expected_replay);
            assert_eq!(node.active().unwrap(), active_before);
            assert_eq!(rows(&node.db), before);
        }
    }
    let id = admit(&mut node, &packet);
    let admitted = rows(&node.db);
    for bad in [&field, &product] {
        assert_eq!(
            node.admit_growth(bad, 100_000).unwrap_err().to_string(),
            "DUPLICATE_CONTENT",
        );
        assert_eq!(rows(&node.db), admitted);
    }
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    assert_eq!(rows(&node.db), admitted);
}

fn cancel_reorg_at(cuts: &[GrowthProgress]) {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let mut old = settings.genesis();
    for height in 1..=2 {
        let packet = make(
            &node,
            old,
            vec![transfer(&settings, 0, height, public(50 + height), 10_000)],
        );
        old = admit(&mut node, &packet);
    }
    let mut fork = settings.genesis();
    for height in 1..=3 {
        let packet = make(
            &node,
            fork,
            vec![transfer(&settings, 0, height, public(60 + height), 10_000)],
        );
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    let before = rows(&node.db);
    let active_before = node.active().unwrap();
    assert_eq!(active_before.0, old);
    for &cut in cuts {
        let calls = AtomicUsize::new(0);
        let error = node
            .growth_activate_with_progress(fork, &|point| {
                if point == cut {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled), "{error:?}");
        assert_eq!(calls.load(Ordering::Relaxed), 1, "{cut:?}");
        assert_eq!(node.active().unwrap(), active_before, "{cut:?}");
        assert_eq!(rows(&node.db), before, "{cut:?}");
    }
    // Each interrupted operation rolled back, leaving the same owner usable.
    assert_eq!(node.growth_activate(fork).unwrap(), fork);
    let active = node.active().unwrap();
    assert_eq!(active.1, active_before.1 + 1);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 4);
    assert_eq!(
        node.growth_account(old, public(0)).unwrap().unwrap().nonce,
        2
    );
    let after = rows(&node.db);
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(rows(&node.db), after);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 4);
    assert_eq!(
        node.growth_account(old, public(0)).unwrap().unwrap().nonce,
        2
    );
}

#[test]
fn native_growth_v2_reorg_ancestor_cancellation_is_atomic() {
    cancel_reorg_at(&[
        GrowthProgress::ReorgAncestor { index: 0 },
        GrowthProgress::ReorgAncestor { index: 4 },
    ]);
}

#[test]
fn native_growth_v2_reorg_write_cancellation_is_atomic() {
    cancel_reorg_at(&[
        GrowthProgress::ReorgWrite { index: 0 },
        GrowthProgress::ReorgWrite { index: 4 },
    ]);
}

#[test]
fn native_growth_v2_reorg_readback_cancellation_is_atomic() {
    cancel_reorg_at(&[
        GrowthProgress::ReorgReadback { index: 0 },
        GrowthProgress::ReorgReadback { index: 12 },
    ]);
}

#[test]
fn native_growth_v2_reorg_readback_preserves_exact_rows_and_singleton() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let old = settings.genesis();
    let packet = make(
        &node,
        old,
        vec![transfer(&settings, 0, 1, public(70), 1_000)],
    );
    let target = admit(&mut node, &packet);
    let generation = node.active().unwrap().1;
    let changes = [(1, target)];
    node.growth_check_latest_journal(old, target, generation, &changes)
        .unwrap();
    let before = rows(&node.db);
    for table in ["steps", "events"] {
        let insert = if table == "steps" {
            "INSERT INTO steps SELECT ordinal+1,kind,block FROM steps"
        } else {
            "INSERT INTO events SELECT generation,ordinal+1,kind,block FROM events"
        };
        for sql in [
            format!("DELETE FROM {table}"),
            insert.to_owned(),
            format!("UPDATE {table} SET ordinal=3"),
            format!("UPDATE {table} SET kind=0"),
            format!("UPDATE {table} SET block=zeroblob(32)"),
        ] {
            let tx = node.db.unchecked_transaction().unwrap();
            tx.execute(&sql, []).unwrap();
            assert!(
                node.growth_check_latest_journal(old, target, generation, &changes)
                    .is_err(),
                "{sql}"
            );
            tx.rollback().unwrap();
            assert_eq!(rows(&node.db), before);
        }
    }
    for sql in [
        "UPDATE reorg SET old_tip=zeroblob(32)",
        "UPDATE reorg SET new_tip=zeroblob(32)",
        "UPDATE reorg SET generation=100",
        "UPDATE reorg SET cursor=0",
        "UPDATE reorg SET done=0",
    ] {
        let tx = node.db.unchecked_transaction().unwrap();
        tx.execute(sql, []).unwrap();
        assert!(
            node.growth_check_latest_journal(old, target, generation, &changes)
                .is_err(),
            "{sql}"
        );
        tx.rollback().unwrap();
        assert_eq!(rows(&node.db), before);
    }
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

#[test]
fn native_growth_v2_and_complete_state_reference_reject_cross_profile_openers() {
    let dir = tempfile::tempdir().unwrap();
    let reference = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::growth_profile_v2::PROFILE,
    )
    .unwrap();
    assert_eq!(
        reference
            .clone()
            .with_permanent_account_growth_v2("forbidden-hybrid")
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_PROFILE_SOURCE"
    );
    let fresh = dir.path().join("never-created");
    assert_eq!(
        Node::open_with_permanent_account_growth_v2(&fresh, reference.clone())
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_PROFILE"
    );
    assert!(!fresh.exists());
    let bounded = settings();
    assert_eq!(
        Node::open(&fresh, bounded.clone(), 1)
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_PROFILE_BACKEND"
    );
    assert!(!fresh.exists());
    let mut hybrid = bounded.clone();
    hybrid.app.params["work_task_profile"] = json!(trnm_mvcc_fee::growth_profile_v2::PROFILE);
    assert_eq!(
        Node::open_with_permanent_account_growth_v2(&fresh, hybrid)
            .err()
            .unwrap()
            .to_string(),
        "GROWTH_PROFILE"
    );
    assert!(!fresh.exists());

    let reference_path = dir.path().join("reference");
    let node = Node::open(&reference_path, reference.clone(), 1).unwrap();
    let reference_rows = rows(&node.db);
    drop(node);
    assert!(Node::open_with_permanent_account_growth_v2(&reference_path, bounded.clone()).is_err());
    let node = Node::open(&reference_path, reference.clone(), 1).unwrap();
    assert_eq!(rows(&node.db), reference_rows);
    drop(node);
    let bounded_path = dir.path().join("bounded");
    let node = Node::open_with_permanent_account_growth_v2(&bounded_path, bounded.clone()).unwrap();
    let bounded_rows = rows(&node.db);
    drop(node);
    assert!(Node::open(&bounded_path, reference, 1).is_err());
    let node = Node::open_with_permanent_account_growth_v2(&bounded_path, bounded).unwrap();
    assert_eq!(rows(&node.db), bounded_rows);
}

#[test]
fn native_growth_v2_cold_open_never_ignores_reference_budget_records() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(10), 1_000)],
    );
    admit(&mut node, &packet);
    drop(node);
    // A recognized but malformed local-observation record must stop cold open;
    // otherwise the early growth return would silently discard its meaning.
    let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
    let key = format!("pon-native-budget-v1:op:{}", hex::encode([166; 32]));
    db.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![key, b"{}".as_slice()],
    )
    .unwrap();
    let before = rows(&db);
    db.close().unwrap();
    let error = Node::open_with_permanent_account_growth_v2(dir.path(), settings)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "BUDGET_RECORD_CODEC");
    let db = Connection::open_with_flags(
        dir.path().join("native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(rows(&db), before);
}

#[path = "mandatory_capacity_tests.rs"]
mod mandatory_capacity;

#[path = "work_checked_tests.rs"]
mod work_checked;
