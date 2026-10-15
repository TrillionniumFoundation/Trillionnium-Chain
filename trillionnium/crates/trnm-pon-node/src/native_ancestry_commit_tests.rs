use super::*;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

pub(super) fn open(path: &Path, settings: Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    } else {
        Node::open(path, settings, 1).unwrap()
    }
}

pub(super) fn logical_rows(db: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<Vec<String>> = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|index| {
                            row.get::<_, rusqlite::types::Value>(index)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

#[test]
fn real_signed_packets_reject_omitted_and_late_modified_ancestry_before_commit() {
    // These are fault injection in a locally owned database, not a claim that
    // a remote packet can install SQL triggers or rewrite local history.
    for authenticated in [false, true] {
        for (prior_blocks, trigger, expected) in [
            (0, "CREATE TRIGGER ancestry_fault BEFORE INSERT ON ancestry_jump BEGIN SELECT RAISE(IGNORE); END;", "STORAGE_WRITE"),
            (1, "CREATE TRIGGER ancestry_fault BEFORE INSERT ON ancestry_jump WHEN NEW.level=1 BEGIN SELECT RAISE(IGNORE); END;", "STORAGE_WRITE"),
            (0, "CREATE TRIGGER ancestry_fault AFTER INSERT ON deltas BEGIN DELETE FROM ancestry_jump WHERE block=NEW.block; END;", "ANCESTRY_INDEX_STRUCTURE"),
            (0, "CREATE TRIGGER ancestry_fault AFTER INSERT ON deltas BEGIN UPDATE ancestry_jump SET seal=zeroblob(32) WHERE block=NEW.block; END;", "ANCESTRY_INDEX_SEAL"),
            (0, "CREATE TRIGGER ancestry_fault AFTER INSERT ON deltas BEGIN INSERT OR IGNORE INTO ancestry_jump SELECT block,10,ancestor,ancestor_height,left_seal,right_seal,seal FROM ancestry_jump WHERE block=NEW.block AND level=0; END;", "ANCESTRY_INDEX_STRUCTURE"),
            (1, "CREATE TRIGGER ancestry_fault AFTER INSERT ON deltas BEGIN UPDATE ancestry_jump SET seal=zeroblob(32) WHERE block=(SELECT parent FROM blocks WHERE id=NEW.block); END;", "ANCESTRY_INDEX_SEAL"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(1)).unwrap();
            let mut node = open(directory.path(), settings.clone(), authenticated);
            let miner = development_public(7).unwrap();
            let sender = development_public(0).unwrap();
            let mut parent = settings.genesis();
            for height in 1..=prior_blocks {
                let packet = node.make(parent, vec![], miner, 1 + height * 10, 4096).unwrap();
                parent = node.admit(&packet, 100_000).unwrap();
                node.activate(parent).unwrap();
            }
            let before = node.read_active().unwrap();
            let nonce = node.next_nonce(sender).unwrap();
            let packet = node.make(parent, vec![transfer(&settings, nonce)], miner, 1 + (prior_blocks + 1) * 10, 4096).unwrap();
            let id = packet.id().unwrap();
            let original_rows = logical_rows(&node.db);
            node.db.execute_batch(trigger).unwrap();
            let error = node.admit(&packet, 100_000).unwrap_err();
            assert_eq!(error.to_string(), expected, "{authenticated}: {trigger}");
            assert!(error.requires_owner_stop());
            assert_eq!(logical_rows(&node.db), original_rows);
            assert_eq!(node.read_active().unwrap(), before);
            assert_eq!(node.next_nonce(sender).unwrap(), nonce);
            assert!(node.record(id).is_err());
            node.db.execute_batch("DROP TRIGGER ancestry_fault").unwrap();
            drop(node);
            let mut node = open(directory.path(), settings.clone(), authenticated);
            assert_eq!(logical_rows(&node.db), original_rows);
            assert_eq!(node.read_active().unwrap(), before);
            assert_eq!(node.admit(&packet, 100_000).unwrap(), id);
            node.activate(id).unwrap();
            assert_eq!(node.next_nonce(sender).unwrap(), nonce + 1);
            drop(node);
            let node = open(directory.path(), settings, authenticated);
            assert_eq!(node.active().unwrap().0, id);
            assert_eq!(node.next_nonce(sender).unwrap(), nonce + 1);
        }
    }
}

#[test]
fn restart_checks_exact_active_tip_row_set_including_genesis() {
    for authenticated in [false, true] {
        for height in [0, 1] {
            let directory = tempfile::tempdir().unwrap();
            let settings = Settings::development(Some(1)).unwrap();
            let mut node = open(directory.path(), settings.clone(), authenticated);
            let genesis = settings.genesis();
            let mut tip = genesis;
            if height > 0 {
                let packet = node
                    .make(genesis, vec![], development_public(7).unwrap(), 11, 4096)
                    .unwrap();
                tip = node.admit(&packet, 100_000).unwrap();
                node.activate(tip).unwrap();
            }
            node.db
                .execute(
                    "INSERT INTO ancestry_jump VALUES(?,10,?,0,?,?,?)",
                    params![
                        tip.as_slice(),
                        genesis.as_slice(),
                        [0_u8; 32].as_slice(),
                        [0_u8; 32].as_slice(),
                        [0_u8; 32].as_slice()
                    ],
                )
                .unwrap();
            let before = logical_rows(&node.db);
            drop(node);
            let error = if authenticated {
                Node::open_with_authenticated_state(directory.path(), settings, 1)
            } else {
                Node::open(directory.path(), settings, 1)
            }
            .err()
            .unwrap();
            assert_eq!(error.to_string(), "ANCESTRY_INDEX_STRUCTURE");
            let db = Connection::open(directory.path().join("native.sqlite")).unwrap();
            assert_eq!(logical_rows(&db), before);
        }
    }
}

#[test]
fn activation_final_events_cannot_commit_missing_or_extra_active_ancestry() {
    for authenticated in [false, true] {
        for mode in 0..3 {
            for (trigger, expected) in [
                ("CREATE TRIGGER ancestry_event_fault AFTER INSERT ON events BEGIN DELETE FROM ancestry_jump WHERE block=NEW.block; END;", "ANCESTRY_INDEX_MISSING"),
                ("CREATE TRIGGER ancestry_event_fault AFTER INSERT ON events BEGIN INSERT OR IGNORE INTO ancestry_jump SELECT block,10,ancestor,ancestor_height,left_seal,right_seal,seal FROM ancestry_jump WHERE block=NEW.block AND level=0; END;", "ANCESTRY_INDEX_STRUCTURE"),
            ] {
                let directory = tempfile::tempdir().unwrap();
                let settings = Settings::development(Some(1)).unwrap();
                let mut node = open(directory.path(), settings.clone(), authenticated);
                let genesis = settings.genesis();
                let mut parent = genesis;
                let mut height = 1;
                if mode == 2 {
                    let selected = node.make(genesis, vec![], development_public(7).unwrap(), 11, 4096).unwrap();
                    let selected_id = node.admit(&selected, 100_000).unwrap();
                    node.activate(selected_id).unwrap();
                    let branch = node.make(genesis, vec![], development_public(8).unwrap(), 11, 4096).unwrap();
                    parent = node.admit(&branch, 100_000).unwrap();
                    height = 2;
                }
                let nonce = node.next_nonce(development_public(0).unwrap()).unwrap();
                let packet = node.make(parent, vec![transfer(&settings, nonce)], development_public(8).unwrap(), 1 + height * 10, 4096).unwrap();
                let id = node.admit(&packet, 100_000).unwrap();
                let before = node.read_active().unwrap();
                let before_rows = logical_rows(&node.db);
                node.db.execute_batch(trigger).unwrap();
                let error = if mode == 1 {
                    node.activate_with_fault(id, Some(&mut |_| Ok(())))
                } else {
                    node.activate(id)
                }.unwrap_err();
                assert_eq!(error.to_string(), expected, "{authenticated}/{mode}: {trigger}");
                assert!(error.requires_owner_stop());
                assert_eq!(node.read_active().unwrap(), before);
                assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), nonce);
                let after_rows = logical_rows(&node.db);
                assert_eq!(after_rows["ancestry_jump"], before_rows["ancestry_jump"]);
                assert_eq!(after_rows["events"], before_rows["events"]);
                if mode == 0 {
                    assert_eq!(after_rows, before_rows);
                } else {
                    let pending: (u64, u64) = node.db.query_row("SELECT cursor,done FROM reorg WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
                    let count: u64 = node.db.query_row("SELECT COUNT(*) FROM steps", [], |row| row.get(0)).unwrap();
                    assert_eq!(pending, (count, 0));
                }
                node.db.execute_batch("DROP TRIGGER ancestry_event_fault").unwrap();
                if mode == 0 {
                    // The admitted child remains eligible. Retry explicitly
                    // before restart, whose ordinary recovery may select it.
                    assert_eq!(node.read_active().unwrap(), before);
                    node.activate(id).unwrap();
                }
                drop(node);
                let node = open(directory.path(), settings.clone(), authenticated);
                // Slow-path stage commits are intentional; cold open resumes
                // their pending intent after the final publication rolled back.
                assert_eq!(node.active().unwrap().0, id);
                assert_eq!(node.next_nonce(development_public(0).unwrap()).unwrap(), nonce + 1);
                drop(node);
                let node = open(directory.path(), settings, authenticated);
                assert_eq!(node.active().unwrap().0, id);
            }
        }
    }
}
