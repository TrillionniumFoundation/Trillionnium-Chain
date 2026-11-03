//! Reorganization-tail controls use real SQLite transactions and current State.
//! Graph-call differences are local work observations, not CPU/service acceptance.
use super::*;
use std::error::Error as _;

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

fn packet(node: &Node, parent: Hash, height: u64) -> Packet {
    node.make_consensus_maintenance(
        parent,
        vec![],
        development_public(7).unwrap(),
        1 + height * 10,
        4096,
    )
    .unwrap()
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

fn active_child() -> Fixture {
    let mut f = fixture(true);
    let block = packet(&f.node, f.node.settings.genesis(), 1);
    let id = f.node.admit(&block, 100_000).unwrap();
    f.node.activate_observed(id, 100_000).unwrap();
    assert_ne!(id, f.node.settings.genesis());
    f
}

fn active_child_with_transfer() -> Fixture {
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::Envelope;

    let mut f = fixture(true);
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: f.node.settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
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
    let genesis = f.node.settings.genesis();
    let block = f
        .node
        .make_consensus_maintenance(
            genesis,
            vec![transaction.encode().unwrap()],
            development_public(7).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = f.node.admit(&block, 100_000).unwrap();
    f.node.activate_observed(id, 100_000).unwrap();
    assert_ne!(id, genesis);
    let accounts = |block: Hash| {
        let bytes: Vec<u8> = f
            .node
            .db
            .query_row(
                "SELECT data FROM native_state_commitments WHERE block=?",
                [block.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_slice::<native_authenticated::Record>(&bytes)
            .unwrap()
            .accounts
    };
    // Keep a real no-hit tail after cross-Record reuse was introduced: an
    // empty maintenance child would share genesis's account graph and consume
    // a hit even when the closure below has not verified its first graph.
    assert_ne!(accounts(id), accounts(genesis));
    f
}

fn tail(
    node: &Node,
    tip: Hash,
    state: &State,
    first_graph: bool,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    node.atomic_reorg_with_readback(progress, |progress, owner| {
        let mut scope = node.reorg_post_write_readback(tip, owner)?;
        assert!(scope.is_some());
        if first_graph {
            node.check_persisted_state_with_readback(tip, state, progress, scope.as_mut())?;
        }
        Ok(scope)
    })
}

#[test]
fn real_reorg_tail_keeps_rows_events_fault_recovery_and_cold_reopen() {
    for (fork, fault) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut accelerated = fixture(true);
        let mut reference = fixture(false);
        let mut target = accelerated.node.settings.genesis();
        if fork {
            let left_packet = accelerated
                .node
                .make_consensus_maintenance(
                    target,
                    vec![],
                    development_public(9).unwrap(),
                    11,
                    4096,
                )
                .unwrap();
            let left = accelerated.node.admit(&left_packet, 100_000).unwrap();
            assert_eq!(reference.node.admit(&left_packet, 100_000).unwrap(), left);
            accelerated.node.activate_observed(left, 100_000).unwrap();
            reference.node.activate_observed(left, 100_000).unwrap();
            assert_ne!(left, target);
        }
        for height in 1..=3 {
            let block = packet(&accelerated.node, target, height);
            target = accelerated.node.admit(&block, 100_000).unwrap();
            assert_eq!(reference.node.admit(&block, 100_000).unwrap(), target);
        }
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let before = (graphs(&accelerated.node), graphs(&reference.node));
        let fault_point = if fork { "attach:1" } else { "attach:0" };
        let mut traces = Vec::new();
        for node in [&mut accelerated.node, &mut reference.node] {
            let mut trace = Vec::new();
            let result = node.activate_with_fault(
                target,
                Some(&mut |point| {
                    trace.push(point.to_owned());
                    if fault && point == fault_point {
                        Err(Error::from("reorg-readback-crash").local_integrity())
                    } else {
                        Ok(())
                    }
                }),
            );
            if fault {
                assert_eq!(result.unwrap_err().to_string(), "reorg-readback-crash");
            } else {
                assert_eq!(result.unwrap(), target);
            }
            traces.push(trace);
        }
        assert_eq!(traces[0], traces[1]);
        assert_eq!(
            traces[0],
            match (fork, fault) {
                (false, true) => vec!["intent", "attach:0"],
                (true, true) => vec!["intent", "detach:0", "attach:1"],
                (false, false) => vec![
                    "intent",
                    "attach:0",
                    "attach:1",
                    "attach:2",
                    "before-publish",
                    "published",
                ],
                (true, false) => vec![
                    "intent",
                    "detach:0",
                    "attach:1",
                    "attach:2",
                    "attach:3",
                    "before-publish",
                    "published",
                ],
            }
        );
        assert_eq!(
            accelerated
                .node
                .db
                .query_row::<u64, _, _>("SELECT COUNT(*) FROM steps WHERE kind=0", [], |row| row
                    .get(0),)
                .unwrap(),
            u64::from(fork)
        );
        assert!(graphs(&accelerated.node) - before.0 < graphs(&reference.node) - before.1);
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        if fault {
            assert_eq!(accelerated.node.recover().unwrap(), target);
            assert_eq!(reference.node.recover().unwrap(), target);
        }
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let expected = reference.node.read_active().unwrap();
        assert_eq!(accelerated.node.read_active().unwrap(), expected);
        let settings = accelerated.node.settings.clone();
        drop(accelerated.node);
        let reopened =
            Node::open_with_authenticated_state(accelerated.directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), expected);
        assert_eq!(facts(&reopened.db), facts(&reference.node.db));
    }
}

#[test]
fn non_genesis_common_ancestor_keeps_every_cut_and_publication_on_cold_reopen() {
    let complete_trace = [
        "intent",
        "detach:0",
        "attach:1",
        "attach:2",
        "before-publish",
        "published",
    ];
    let ordered_rows = |node: &Node, sql: &str, parameters: &[u64]| {
        node.db
            .prepare(sql)
            .unwrap()
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    for cut_at in [
        None,
        Some("intent"),
        Some("detach:0"),
        Some("attach:1"),
        Some("attach:2"),
        Some("before-publish"),
        Some("published"),
    ] {
        let mut accelerated = fixture(true);
        let mut reference = fixture(false);
        assert!(accelerated.node.state_backend == StateBackend::AuthenticatedV1);
        assert!(reference.node.state_backend == StateBackend::AuthenticatedV1);
        assert!(accelerated.node.post_write_schema.is_some());
        assert!(reference.node.post_write_schema.is_none());
        let genesis = accelerated.node.settings.genesis();
        let common_packet = packet(&accelerated.node, genesis, 1);
        let common = accelerated.node.admit(&common_packet, 100_000).unwrap();
        assert_eq!(
            reference.node.admit(&common_packet, 100_000).unwrap(),
            common
        );
        accelerated.node.activate_observed(common, 100_000).unwrap();
        reference.node.activate_observed(common, 100_000).unwrap();
        let left_packet = accelerated
            .node
            .make_consensus_maintenance(common, vec![], development_public(9).unwrap(), 21, 4096)
            .unwrap();
        let left = accelerated.node.admit(&left_packet, 100_000).unwrap();
        assert_eq!(reference.node.admit(&left_packet, 100_000).unwrap(), left);
        accelerated.node.activate_observed(left, 100_000).unwrap();
        reference.node.activate_observed(left, 100_000).unwrap();
        let right_packet = packet(&accelerated.node, common, 2);
        let right = accelerated.node.admit(&right_packet, 100_000).unwrap();
        assert_eq!(reference.node.admit(&right_packet, 100_000).unwrap(), right);
        let target_packet = packet(&accelerated.node, right, 3);
        let target = accelerated.node.admit(&target_packet, 100_000).unwrap();
        assert_eq!(
            reference.node.admit(&target_packet, 100_000).unwrap(),
            target
        );
        // Distinct children of the same height-one block make that block the
        // actual common ancestor, rather than merely a non-genesis active tip.
        assert_ne!(common, genesis);
        assert_ne!(left, right);
        assert_eq!(accelerated.node.record(common).unwrap().height, 1);
        assert_eq!(accelerated.node.parent(left).unwrap(), common);
        assert_eq!(accelerated.node.parent(right).unwrap(), common);
        assert_eq!(accelerated.node.parent(target).unwrap(), right);
        let old = accelerated.node.read_active().unwrap();
        assert_eq!(old.0, left);
        assert_eq!(reference.node.read_active().unwrap(), old);
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let generation = old.1 + 1;
        let expected_steps = vec![
            (0, 0, left.to_vec()),
            (1, 1, right.to_vec()),
            (2, 1, target.to_vec()),
        ];
        let old_events = ordered_rows(
            &reference.node,
            "SELECT ordinal,kind,block FROM events WHERE generation<? ORDER BY generation,ordinal",
            &[generation],
        );
        let before = (graphs(&accelerated.node), graphs(&reference.node));
        let expected_length = cut_at.map_or(complete_trace.len(), |cut| {
            complete_trace
                .iter()
                .position(|point| *point == cut)
                .unwrap()
                + 1
        });
        let expected_trace: Vec<String> = complete_trace[..expected_length]
            .iter()
            .map(|point| (*point).to_owned())
            .collect();
        for node in [&mut accelerated.node, &mut reference.node] {
            let mut trace = Vec::new();
            let outcome = node.activate_with_fault(
                target,
                Some(&mut |point| {
                    trace.push(point.to_owned());
                    if Some(point) == cut_at {
                        Err(Error::from("reorg-non-genesis-cut").local_integrity())
                    } else {
                        Ok(())
                    }
                }),
            );
            if cut_at.is_some() {
                assert_eq!(outcome.unwrap_err().to_string(), "reorg-non-genesis-cut");
            } else {
                assert_eq!(outcome.unwrap(), target);
            }
            assert_eq!(trace, expected_trace);
        }
        assert!(graphs(&accelerated.node) - before.0 < graphs(&reference.node) - before.1);
        assert_eq!(facts(&accelerated.node.db), facts(&reference.node.db));
        let published = cut_at.is_none() || cut_at == Some("published");
        for node in [&accelerated.node, &reference.node] {
            assert_eq!(
                ordered_rows(
                    node,
                    "SELECT ordinal,kind,block FROM steps ORDER BY ordinal",
                    &[]
                ),
                expected_steps
            );
            let events = ordered_rows(
                node,
                "SELECT ordinal,kind,block FROM events WHERE generation=? ORDER BY ordinal",
                &[generation],
            );
            if published {
                assert_eq!(events, expected_steps);
                assert_eq!(node.active().unwrap(), (target, generation));
            } else {
                assert!(events.is_empty());
                assert_eq!(node.read_active().unwrap(), old);
            }
        }
        // The scoped path cold-opens the actual retained cut, including an
        // unfinished intent. Its oracle resumes with graph reuse disabled.
        let settings = accelerated.node.settings.clone();
        drop(accelerated.node);
        let mut reopened =
            Node::open_with_authenticated_state(accelerated.directory.path(), settings.clone(), 1)
                .unwrap();
        assert_eq!(reference.node.recover().unwrap(), target);
        let expected = reference.node.read_active().unwrap();
        assert_eq!(expected.0, target);
        assert_eq!(expected.1, generation);
        assert_eq!(reopened.read_active().unwrap(), expected);
        assert_eq!(facts(&reopened.db), facts(&reference.node.db));
        for node in [&reopened, &reference.node] {
            node.check_reorg_row(left, target, generation, 3, 1)
                .unwrap();
            assert_eq!(
                ordered_rows(
                    node,
                    "SELECT ordinal,kind,block FROM events WHERE generation=? ORDER BY ordinal",
                    &[generation],
                ),
                expected_steps
            );
            assert_eq!(
                ordered_rows(
                    node,
                    "SELECT ordinal,kind,block FROM events WHERE generation<? ORDER BY generation,ordinal",
                    &[generation],
                ),
                old_events
            );
        }
        let completed = facts(&reference.node.db);
        drop(reference.node);
        let mut reference_reopened =
            Node::open_with_authenticated_state(reference.directory.path(), settings, 1).unwrap();
        reference_reopened.post_write_schema = None;
        for node in [&mut reopened, &mut reference_reopened] {
            assert_eq!(node.recover().unwrap(), target);
            assert_eq!(node.read_active().unwrap(), expected);
            assert_eq!(facts(&node.db), completed);
        }
    }
}

#[test]
fn no_scope_keeps_full_graphs_and_rejects_transaction_replacement_with_cancel_source() {
    let f = fixture(false);
    let expected = f.node.read_active().unwrap();
    let original = facts(&f.node.db);
    let run = |progress: &mut dyn FnMut() -> Result<()>| {
        f.node
            .atomic_reorg_with_readback(progress, |progress, owner| {
                // None disables graph reuse, not the authenticated original-writer
                // identity check. It does NOT promise a strict write-epoch fence.
                assert!(owner.is_some());
                let scope = f.node.reorg_post_write_readback(expected.0, owner)?;
                assert!(scope.is_none());
                f.node.check_persisted_state_with_readback(
                    expected.0,
                    &expected.2,
                    progress,
                    None,
                )?;
                Ok(scope)
            })
    };
    let mut callbacks = 0;
    let before = graphs(&f.node);
    run(&mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    // First persisted State, actual active State, and genesis history all retain
    // their full traversal even though the three Records happen to be equal.
    assert_eq!(graphs(&f.node) - before, 3);
    assert_eq!(facts(&f.node.db), original);
    for sql in ["COMMIT; BEGIN IMMEDIATE", "ROLLBACK; BEGIN IMMEDIATE"] {
        for cancel in [false, true] {
            let mut current = 0;
            let error = run(&mut || {
                current += 1;
                if current == callbacks {
                    f.node.db.execute_batch(sql)?;
                    if cancel {
                        return Err(Error::new(crate::ErrorCode::PublicRequestCancelled));
                    }
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(current, callbacks);
            assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
            assert!(error.requires_owner_stop());
            if cancel {
                assert!(error
                    .source()
                    .unwrap()
                    .downcast_ref::<Error>()
                    .unwrap()
                    .is(crate::ErrorCode::PublicRequestCancelled));
            }
            assert!(f.node.db.is_autocommit());
            assert_eq!(facts(&f.node.db), original);
            assert_eq!(f.node.read_active().unwrap(), expected);
        }
    }
    run(&mut || Ok(())).unwrap();
    assert_eq!(facts(&f.node.db), original);
}

#[test]
fn final_callback_writes_fail_with_or_without_a_consumed_graph_hit() {
    for first_graph in [false, true] {
        let f = active_child_with_transfer();
        let (tip, generation, state) = f.node.read_active().unwrap();
        let mut callbacks = 0;
        let before = graphs(&f.node);
        tail(&f.node, tip, &state, first_graph, &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap();
        // Without the closure's first graph, active and genesis each run once:
        // the strict final fence must not depend on an earlier consumed hit.
        assert_eq!(graphs(&f.node) - before, 2);
        for (sql, failed_statement, expected) in [
            ("UPDATE archive_nodes SET data=data WHERE 0", false, "NATIVE_POST_WRITE_CHANGED"),
            ("UPDATE archive_nodes SET data=x'00' WHERE id=(SELECT id FROM archive_nodes ORDER BY id LIMIT 1)", false, "NATIVE_POST_WRITE_CHANGED"),
            ("INSERT INTO active SELECT * FROM active", true, "NATIVE_POST_WRITE_CHANGED"),
            ("CREATE TABLE tail_probe(x); DROP TABLE tail_probe", false, "NATIVE_POST_WRITE_CHANGED"),
            ("SAVEPOINT tail_probe; UPDATE archive_nodes SET data=data WHERE 0; ROLLBACK TO tail_probe; RELEASE tail_probe", false, "NATIVE_POST_WRITE_SCOPE"),
            ("COMMIT; BEGIN IMMEDIATE", false, "NATIVE_POST_WRITE_SCOPE"),
        ] {
            let original = facts(&f.node.db);
            let mut current = 0;
            let error = tail(&f.node, tip, &state, first_graph, &mut || {
                current += 1;
                if current == callbacks {
                    let write = f.node.db.execute_batch(sql);
                    if failed_statement {
                        assert_eq!(write.unwrap_err().sqlite_error_code(), Some(rusqlite::ErrorCode::ConstraintViolation));
                    } else {
                        write?;
                    }
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(current, callbacks);
            assert!(error.to_string().starts_with(expected), "{sql}: {error}");
            assert!(error.requires_owner_stop());
            assert_eq!(facts(&f.node.db), original);
            assert_eq!(f.node.read_active().unwrap(), (tip, generation, state.clone()));
        }
    }
}

#[test]
fn prehit_write_cannot_restamp_and_callback_errors_keep_original_precedence() {
    let f = active_child();
    let expected = f.node.read_active().unwrap();
    let (tip, _, state) = &expected;
    let mut current = 0;
    let error = tail(&f.node, *tip, state, true, &mut || {
        current += 1;
        if current == 2 {
            f.node
                .db
                .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(current > 2);
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert_eq!(f.node.read_active().unwrap(), expected);

    let mut callbacks = 0;
    tail(&f.node, *tip, state, true, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    for sql in [
        "UPDATE archive_nodes SET data=data WHERE 0",
        "ROLLBACK; BEGIN IMMEDIATE",
    ] {
        let mut current = 0;
        let error = tail(&f.node, *tip, state, true, &mut || {
            current += 1;
            if current == callbacks {
                f.node.db.execute_batch(sql)?;
                return Err(Error::new(crate::ErrorCode::PublicRequestCancelled));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(current, callbacks);
        if sql.starts_with("UPDATE") {
            assert!(error.is(crate::ErrorCode::PublicRequestCancelled));
            assert!(!error.requires_owner_stop());
        } else {
            assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
            assert!(error.requires_owner_stop());
            assert!(error
                .source()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .is(crate::ErrorCode::PublicRequestCancelled));
        }
        assert_eq!(f.node.read_active().unwrap(), expected);
    }
}

#[test]
fn original_write_lock_blocks_foreign_writer_and_no_scope_survives_commit() {
    let f = active_child();
    let expected = f.node.read_active().unwrap();
    let foreign = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    foreign.busy_timeout(Duration::ZERO).unwrap();
    let mut attempted = false;
    tail(&f.node, expected.0, &expected.2, true, &mut || {
        if !attempted && !f.node.db.is_autocommit() {
            let error = foreign
                .execute("UPDATE archive_nodes SET data=data WHERE 0", [])
                .unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            attempted = true;
        }
        Ok(())
    })
    .unwrap();
    assert!(attempted);
    let id = native_authenticated::load(&f.node.db, expected.0)
        .unwrap()
        .accounts
        .node
        .unwrap();
    let data: Vec<u8> = foreign
        .query_row(
            "SELECT data FROM archive_nodes WHERE id=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        foreign
            .execute(
                "UPDATE archive_nodes SET data=x'00' WHERE id=?",
                [id.as_slice()]
            )
            .unwrap(),
        1
    );
    assert!(f.node.read_active().unwrap_err().requires_owner_stop());
    assert_eq!(
        foreign
            .execute(
                "UPDATE archive_nodes SET data=? WHERE id=?",
                params![data, id.as_slice()]
            )
            .unwrap(),
        1
    );
    assert_eq!(f.node.read_active().unwrap(), expected);
}
