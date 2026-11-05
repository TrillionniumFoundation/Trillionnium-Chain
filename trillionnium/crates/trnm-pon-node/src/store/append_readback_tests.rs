//! Actual direct-append controls, including signed transfers and every
//! cancellable boundary before the one durable publication.
use super::*;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
}

fn fixture(enabled: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    if !enabled {
        node.post_write_schema = None;
    }
    Fixture { node, directory }
}

fn packet(node: &Node, transfer: bool) -> Packet {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;

    let mut transactions = Vec::new();
    if transfer {
        let mut payload = development_public(1).unwrap().to_vec();
        payload.extend(1_u64.to_le_bytes());
        let mut transaction = Envelope {
            network: node.settings.network(),
            sender: development_public(0).unwrap(),
            nonce: 1,
            expiry: 2000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        let key =
            signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
                .unwrap();
        transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        transactions.push(transaction.encode().unwrap());
    }
    node.make_consensus_maintenance(
        node.settings.genesis(),
        transactions,
        development_public(7).unwrap(),
        11,
        4096,
    )
    .unwrap()
}

fn facts(db: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| {
                            row.get::<_, rusqlite::types::Value>(column)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}

fn graphs(node: &Node) -> u64 {
    node.native_history_arithmetic_observation()["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["stage"] == "account_graph")
        .unwrap()["totals"]["calls"]
        .as_u64()
        .unwrap()
}

fn commits(node: &Node, site: native_authenticated::SqlCommitSite) -> u64 {
    node.native_history_arithmetic_observation()["sql_commit"]["sites"][site as usize]["totals"]
        ["calls_succeeded"]
        .as_u64()
        .unwrap()
}

#[test]
fn direct_append_keeps_complete_rows_events_state_and_cold_reopen() {
    for transfer in [false, true] {
        let mut accelerated = fixture(true);
        let mut reference = fixture(false);
        let block = packet(&accelerated.node, transfer);
        let target = accelerated.node.admit(&block, 100_000).unwrap();
        assert_eq!(reference.node.admit(&block, 100_000).unwrap(), target);
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let before = (graphs(&accelerated.node), graphs(&reference.node));
        let atomic = commits(
            &accelerated.node,
            native_authenticated::SqlCommitSite::Atomic,
        );
        let reorg = commits(
            &accelerated.node,
            native_authenticated::SqlCommitSite::ReorgStep,
        );
        assert_eq!(
            accelerated.node.activate_observed(target, 100_000).unwrap(),
            target
        );
        assert_eq!(
            reference.node.activate_observed(target, 100_000).unwrap(),
            target
        );
        let traversals = (
            graphs(&accelerated.node) - before.0,
            graphs(&reference.node) - before.1,
        );
        assert!(traversals.0 <= traversals.1);
        if !transfer {
            assert!(traversals.0 < traversals.1);
        }
        assert_eq!(
            commits(
                &accelerated.node,
                native_authenticated::SqlCommitSite::Atomic
            ),
            atomic + 1
        );
        assert_eq!(
            commits(
                &accelerated.node,
                native_authenticated::SqlCommitSite::ReorgStep
            ),
            reorg
        );
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let expected = reference.node.read_active().unwrap();
        assert_eq!(accelerated.node.read_active().unwrap(), expected);
        assert_eq!(expected.0, target);
        let settings = accelerated.node.settings.clone();
        drop(accelerated.node);
        let reopened =
            Node::open_with_authenticated_state(accelerated.directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), expected);
        assert_eq!(facts(&reopened.db), facts(&reference.node.db));
    }
}

#[test]
fn direct_append_cancellation_at_each_callback_leaves_no_partial_publication() {
    for transfer in [false, true] {
        let mut measured = fixture(true);
        let block = packet(&measured.node, transfer);
        let target = measured.node.admit(&block, 100_000).unwrap();
        let mut callbacks = 0;
        assert_eq!(
            measured
                .node
                .activate_observed_with_progress(target, 100_000, &mut || {
                    callbacks += 1;
                    Ok(())
                })
                .unwrap(),
            target
        );
        assert!(callbacks > 10);
        let mut cancelled = fixture(true);
        assert_eq!(cancelled.node.admit(&block, 100_000).unwrap(), target);
        let original = facts(&cancelled.node.db);
        let old = cancelled.node.read_active().unwrap();
        let commits_before = commits(&cancelled.node, native_authenticated::SqlCommitSite::Atomic);
        for cut in 1..=callbacks {
            let mut current = 0;
            let error = cancelled
                .node
                .activate_observed_with_progress(target, 100_000, &mut || {
                    current += 1;
                    if current == cut {
                        Err(Error::new(crate::ErrorCode::PublicRequestCancelled))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(
                error.is(crate::ErrorCode::PublicRequestCancelled),
                "{cut}: {error}"
            );
            assert_eq!(current, cut);
            assert!(cancelled.node.db.is_autocommit());
            assert_eq!(facts(&cancelled.node.db), original, "cut {cut}");
            assert_eq!(cancelled.node.read_active().unwrap(), old, "cut {cut}");
            assert_eq!(
                commits(&cancelled.node, native_authenticated::SqlCommitSite::Atomic),
                commits_before
            );
        }
        assert_eq!(
            cancelled.node.activate_observed(target, 100_000).unwrap(),
            target
        );
        assert_eq!(facts(&cancelled.node.db), facts(&measured.node.db));
        let expected = measured.node.read_active().unwrap();
        let settings = cancelled.node.settings.clone();
        drop(cancelled.node);
        let reopened =
            Node::open_with_authenticated_state(cancelled.directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), expected);
        assert_eq!(facts(&reopened.db), facts(&measured.node.db));
    }
}
