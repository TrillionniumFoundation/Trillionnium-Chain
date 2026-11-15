//! Original Growth admission must honor the caller's control while its one
//! transaction owns partially written/read-back deltas. These are actual signed
//! transfers, native W1, SQLite rows and cold recovery, not a request-time model.
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{
    development_public, Error, ErrorCode, GrowthPacket, GrowthProgress, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

const TRANSFERS: u64 = 256;
type Rows = BTreeMap<String, Vec<Vec<String>>>;

#[derive(Clone, Copy, Debug)]
enum Cut {
    Write,
    Readback,
}

impl Cut {
    fn index(self, point: GrowthProgress) -> Option<usize> {
        match (self, point) {
            (Self::Write, GrowthProgress::AdmissionDeltaWrite { index }) => Some(index),
            (Self::Readback, GrowthProgress::AdmissionDeltaReadback { checkpoint }) => {
                Some(checkpoint)
            }
            _ => None,
        }
    }
}

fn signed_packet() -> (Settings, GrowthPacket) {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("growth-persistence-cancellation-native")
    .unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    let transactions = (0..TRANSFERS)
        .map(|index| {
            let mut payload = development_public(10_000 + index).unwrap().to_vec();
            payload.extend(1_000u64.to_le_bytes());
            let mut tx = Envelope {
                network: settings.network(),
                sender: development_public(0).unwrap(),
                nonce: index + 1,
                expiry: 2000,
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
        })
        .collect();
    let source_dir = tempfile::tempdir().unwrap();
    let source =
        Node::open_with_permanent_account_growth_v2(source_dir.path(), settings.clone()).unwrap();
    let packet = source
        .make_growth_consensus_maintenance(
            settings.genesis(),
            transactions,
            development_public(3).unwrap(),
            11,
            4096,
        )
        .unwrap();
    (settings, packet)
}

fn read_connection(path: &Path) -> Connection {
    Connection::open_with_flags(path.join("native.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
}

fn rows(path: &Path) -> Rows {
    let db = read_connection(path);
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
            let mut values: Vec<Vec<String>> = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| {
                            row.get::<_, rusqlite::types::Value>(column)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            values.sort();
            (table, values)
        })
        .collect()
}

fn cancel_and_retry(cut: Cut) {
    let (settings, packet) = signed_packet();
    let sender = development_public(0).unwrap();
    for code in [
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicRequestDeadline,
        ErrorCode::PublicMutationCpuBudget,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let before = rows(directory.path());
        let active_before = node.active().unwrap();
        let nonce_before = node.next_nonce(sender).unwrap();
        let seen = Mutex::new(Vec::new());
        let cancelled = AtomicBool::new(false);
        let error = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                assert!(
                    !cancelled.load(Ordering::Acquire),
                    "admission continued its callbacks after {cut:?} returned {code:?}"
                );
                if let Some(index) = cut.index(point) {
                    seen.lock().unwrap().push(index);
                    // Write: one delta was already inserted. Readback: the
                    // existing cursor has read 256 rows and more remain.
                    if index == 1 {
                        cancelled.store(true, Ordering::Release);
                        return Err(Error::new(code));
                    }
                }
                Ok(())
            })
            .expect_err("the original caller control must abort admission before commit");
        assert!(error.is(code), "{cut:?}: {code:?} became {error}");
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(*seen.lock().unwrap(), [0, 1]);
        assert_eq!(rows(directory.path()), before);
        assert_eq!(node.active().unwrap(), active_before);
        assert_eq!(node.next_nonce(sender).unwrap(), nonce_before);
        assert!(node.growth_packet(packet.id().unwrap()).is_err());

        // A new native owner must see no partial packet, delta, COW node,
        // generation or nonce left behind by either refusal point.
        drop(node);
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        assert_eq!(rows(directory.path()), before);
        assert_eq!(node.active().unwrap(), active_before);
        assert_eq!(node.next_nonce(sender).unwrap(), nonce_before);

        let writes = Mutex::new(Vec::new());
        let reads = Mutex::new(Vec::new());
        let id = node
            .admit_growth_with_progress(&packet, 100_000, &|point| {
                match point {
                    GrowthProgress::AdmissionDeltaWrite { index } => {
                        writes.lock().unwrap().push(index)
                    }
                    GrowthProgress::AdmissionDeltaReadback { checkpoint } => {
                        reads.lock().unwrap().push(checkpoint)
                    }
                    _ => (),
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(id, packet.id().unwrap());
        let delta_count: usize = read_connection(directory.path())
            .query_row(
                "SELECT count(*) FROM deltas WHERE block=?",
                [id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            delta_count > 256,
            "the readback refusal must be inside a multi-chunk cursor"
        );
        assert_eq!(
            *writes.lock().unwrap(),
            (0..delta_count).collect::<Vec<_>>()
        );
        assert_eq!(
            *reads.lock().unwrap(),
            (0..2 + delta_count / 256).collect::<Vec<_>>()
        );
        assert_eq!(node.active().unwrap(), active_before);
        assert_eq!(node.activate(id).unwrap(), id);
        assert_eq!(node.next_nonce(sender).unwrap(), TRANSFERS + 1);
        for index in [0, TRANSFERS - 1] {
            let account = node
                .growth_account(id, development_public(10_000 + index).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!((account.balance, account.nonce), (1000, 0));
        }
        assert_eq!(
            node.growth_packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
        let committed = rows(directory.path());
        let active = node.active().unwrap();
        drop(node);
        let reopened =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        assert_eq!(reopened.active().unwrap(), active);
        assert_eq!(reopened.next_nonce(sender).unwrap(), TRANSFERS + 1);
        assert_eq!(rows(directory.path()), committed);
    }
}

#[test]
fn growth_admission_delta_write_control_rolls_back_and_retries_after_cold_open() {
    cancel_and_retry(Cut::Write);
}

#[test]
fn growth_admission_delta_readback_control_rolls_back_and_retries_after_cold_open() {
    cancel_and_retry(Cut::Readback);
}
