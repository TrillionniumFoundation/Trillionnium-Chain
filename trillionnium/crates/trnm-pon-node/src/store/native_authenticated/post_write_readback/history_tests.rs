//! Real SQLite history-readback controls. Statement VM counters observe actual
//! execution attempts, including schema retries, without replacing the original
//! transaction-scope trace hook. RUN is not a logical-query or row-read count.
use super::super::{
    load_observed, verify_history_with_cache, verify_history_with_readback, DELTA_ROWS_SQL,
    NATIVE_BLOCK_SQL, NATIVE_PARENT_SQL,
};
use super::tests::{capture, fixture, verify, Fixture};
use super::*;
use crate::Node;
use rusqlite::StatementStatus;

const HISTORY_SQL: [&str; 5] = [
    "SELECT substr(data,1,?) FROM native_state_commitments WHERE block=?",
    NATIVE_BLOCK_SQL,
    NATIVE_PARENT_SQL,
    DELTA_ROWS_SQL,
    "SELECT state FROM snapshots WHERE block=?",
];

#[derive(Debug)]
struct SqlCounts {
    runs: [i32; 5],
    reprepares: [i32; 5],
    steps: [i32; 5],
}

fn take_sql_counts(db: &Connection) -> SqlCounts {
    let mut counts = SqlCounts {
        runs: [0; 5],
        reprepares: [0; 5],
        steps: [0; 5],
    };
    for (index, sql) in HISTORY_SQL.into_iter().enumerate() {
        let statement = db.prepare_cached(sql).unwrap();
        counts.runs[index] = statement.reset_status(StatementStatus::Run);
        counts.reprepares[index] = statement.reset_status(StatementStatus::RePrepare);
        counts.steps[index] = statement.reset_status(StatementStatus::VmStep);
    }
    counts
}

fn account_graph_calls(node: &Node) -> u64 {
    node.native_history_arithmetic_observation()["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["stage"] == "account_graph")
        .unwrap()["totals"]["calls"]
        .as_u64()
        .unwrap()
}

fn history(
    node: &Node,
    block: Hash,
    scope: &mut PostWriteReadback<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    verify_history_with_readback(
        &node.db,
        &node.settings,
        block,
        progress,
        Some(&node.authenticated_arithmetic),
        Some(scope),
    )
}

fn chain(length: u64) -> (Fixture, Vec<Hash>) {
    let mut f = fixture();
    let mut ids = vec![f.node.settings.genesis()];
    for height in 1..=length {
        let packet = f
            .node
            .make_consensus_maintenance(
                *ids.last().unwrap(),
                vec![],
                crate::development_public(7).unwrap(),
                height + 10,
                4096,
            )
            .unwrap();
        ids.push(f.node.admit(&packet, 100_000).unwrap());
    }
    // Keep every observed VM in the cache; the two compared readers use the
    // same connection/capacity/SQL programs, without changing their SQL rows.
    f.node.db.set_prepared_statement_cache_capacity(128);
    (f, ids)
}

fn mint_genesis_history(node: &Node) -> PostWriteReadback<'_> {
    node.db.set_prepared_statement_cache_capacity(128);
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(node, node.settings.genesis());
    history(node, node.settings.genesis(), &mut scope, &mut || Ok(())).unwrap();
    assert!(!scope.consumed);
    assert_eq!(scope.history_hits, 0);
    assert!(scope.histories.iter().any(Option::is_some));
    scope
}

#[test]
fn completed_parent_suffix_reduces_real_sql_reads_only_for_the_four_named_records() {
    let (mut f, ids) = chain(6);
    f.node.activate_observed(ids[3], 100_000).unwrap();
    let child_state = f.node.state_at(ids[6]).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[6]);
    verify(&f.node, ids[6], &child_state, &mut scope, &mut || Ok(())).unwrap();
    f.node
        .read_active_with_readback(&mut || Ok(()), Some(&mut scope))
        .unwrap();
    assert!(scope.histories.iter().all(Option::is_none));
    assert_eq!(
        scope.ids,
        [Some(ids[6]), Some(ids[0]), Some(ids[5]), Some(ids[3])]
    );
    history(&f.node, ids[6], &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.history_hits, 0);
    assert!(scope.histories.iter().all(Option::is_some));

    take_sql_counts(&f.node.db);
    verify_history_with_cache(
        &f.node.db,
        &f.node.settings,
        ids[5],
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    let original = take_sql_counts(&f.node.db);
    let mut callbacks = 0;
    history(&f.node, ids[5], &mut scope, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    let reused = take_sql_counts(&f.node.db);
    // SQL order: authenticated Record, native block, native parent, deltas,
    // genesis snapshot. Both reads execute every check on the current start.
    assert_eq!(original.runs, [12, 7, 5, 7, 1]);
    assert_eq!(reused.runs, [2, 1, 1, 1, 0]);
    assert_eq!(original.reprepares, [0; 5]);
    assert_eq!(reused.reprepares, [0; 5]);
    for (full, reused) in original.steps.iter().zip(reused.steps) {
        assert!(*full > reused);
    }
    // Entry, all three original current-delta boundaries and output remain.
    // No synthetic callbacks impersonate the skipped immutable suffix work.
    assert_eq!(callbacks, 5);
    assert_eq!(scope.history_hits, 1);
    assert!(scope.consumed);
    println!(
        "{}",
        serde_json::json!({
            "history_blocks": 5,
            "sql_order": ["record", "block", "parent", "delta", "genesis_snapshot"],
            "full_runs": original.runs,
            "reused_runs": reused.runs,
            "full_reprepares": original.reprepares,
            "reused_reprepares": reused.reprepares,
            "counter_scope": "SQLite VM execution attempts; not logical queries or row reads",
            "full_vm_steps": original.steps,
            "reused_vm_steps": reused.steps,
            "reused_progress": callbacks,
        })
    );

    for index in [0, 3, 6] {
        history(&f.node, ids[index], &mut scope, &mut || Ok(())).unwrap();
    }
    assert_eq!(scope.history_hits, 4);
    take_sql_counts(&f.node.db);
    // This fifth record was seen by the original walk but was not nominated.
    // Reaching the already verified active ancestor does not shorten its walk.
    for _ in 0..2 {
        history(&f.node, ids[4], &mut scope, &mut || Ok(())).unwrap();
        assert_eq!(take_sql_counts(&f.node.db).runs, [10, 6, 4, 6, 1]);
        assert_eq!(scope.history_hits, 4);
    }
    scope.validate_consumed(&f.node.db).unwrap();
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn incomplete_history_preserves_full_walk_callbacks_and_mints_no_suffix() {
    let (f, ids) = chain(3);
    let mut full_callbacks = 0;
    verify_history_with_cache(
        &f.node.db,
        &f.node.settings,
        ids[3],
        &mut || {
            full_callbacks += 1;
            Ok(())
        },
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[3]);
    let mut scoped_callbacks = 0;
    history(&f.node, ids[3], &mut scope, &mut || {
        scoped_callbacks += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(scoped_callbacks, full_callbacks);
    f.node.db.execute_batch("ROLLBACK").unwrap();

    for cancel_at in [1, full_callbacks / 2, full_callbacks] {
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = capture(&f.node, ids[3]);
        let mut current = 0;
        let error = history(&f.node, ids[3], &mut scope, &mut || {
            current += 1;
            if current == cancel_at {
                Err("HISTORY_READBACK_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "HISTORY_READBACK_CANCELLED");
        assert_eq!(current, cancel_at);
        assert!(scope.histories.iter().all(Option::is_none));
        assert_eq!(scope.history_hits, 0);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn every_remaining_history_hit_boundary_preserves_cancellation() {
    let f = fixture();
    let mut scope = mint_genesis_history(&f.node);
    for cancel_at in 1..=5 {
        let mut current = 0;
        let error = history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
            current += 1;
            if current == cancel_at {
                Err("HISTORY_READBACK_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "HISTORY_READBACK_CANCELLED");
        assert_eq!(current, cancel_at);
        assert_eq!(scope.history_hits, 0);
        assert!(!scope.consumed);
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn first_history_hit_final_write_repeats_the_original_full_verifier() {
    let f = fixture();
    let mut scope = mint_genesis_history(&f.node);
    take_sql_counts(&f.node.db);
    let mut current = 0;
    history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
        current += 1;
        if current == 5 {
            f.node
                .db
                .execute("UPDATE native_state_commitments SET data=data WHERE 0", [])?;
        }
        Ok(())
    })
    .unwrap();
    assert!(current > 5);
    assert_eq!(take_sql_counts(&f.node.db).runs, [3, 3, 0, 3, 1]);
    assert_eq!(scope.history_hits, 0);
    assert!(!scope.consumed);
    assert!(!scope.enabled);
    assert!(scope.histories.iter().all(Option::is_none));
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn full_history_final_callback_write_cannot_publish_pending_suffixes() {
    let f = fixture();
    let mut full_callbacks = 0;
    verify_history_with_cache(
        &f.node.db,
        &f.node.settings,
        f.node.settings.genesis(),
        &mut || {
            full_callbacks += 1;
            Ok(())
        },
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, f.node.settings.genesis());
    let mut current = 0;
    history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
        current += 1;
        if current == full_callbacks {
            f.node
                .db
                .execute("UPDATE snapshots SET state=state WHERE 0", [])?;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(current, full_callbacks);
    assert!(scope.histories.iter().all(Option::is_none));
    assert!(!scope.enabled);
    assert!(!scope.consumed);
    assert_eq!(scope.history_hits, 0);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn writes_restoration_and_prepare_only_schema_changes_disable_completed_history() {
    for change in ["no-row", "restored-bytes", "reversed-ddl", "prepare-only"] {
        let f = fixture();
        let mut full_callbacks = 0;
        let reference_graphs = account_graph_calls(&f.node);
        verify_history_with_cache(
            &f.node.db,
            &f.node.settings,
            f.node.settings.genesis(),
            &mut || {
                full_callbacks += 1;
                Ok(())
            },
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap();
        assert_eq!(account_graph_calls(&f.node) - reference_graphs, 1);
        let mut scope = mint_genesis_history(&f.node);
        match change {
            "no-row" => {
                f.node
                    .db
                    .execute("UPDATE snapshots SET state=state WHERE 0", [])
                    .unwrap();
            }
            "restored-bytes" => {
                let bytes: Vec<u8> = f
                    .node
                    .db
                    .query_row(
                        "SELECT state FROM snapshots WHERE block=?",
                        [f.node.settings.genesis().as_slice()],
                        |row| row.get(0),
                    )
                    .unwrap();
                f.node
                    .db
                    .execute("UPDATE snapshots SET state=x'00'", [])
                    .unwrap();
                f.node
                    .db
                    .execute("UPDATE snapshots SET state=?", [bytes])
                    .unwrap();
            }
            "reversed-ddl" => {
                f.node
                    .db
                    .execute_batch("CREATE TABLE history_probe(x); DROP TABLE history_probe")
                    .unwrap();
            }
            "prepare-only" => {
                drop(f.node.db.prepare("PRAGMA writable_schema=ON").unwrap());
            }
            _ => unreachable!(),
        }
        take_sql_counts(&f.node.db);
        for pass in 0..2 {
            let before_graphs = account_graph_calls(&f.node);
            let mut callbacks = 0;
            history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
                callbacks += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(scope.history_hits, 0, "{change}");
            assert!(scope.histories.iter().all(Option::is_none), "{change}");
            assert!(!scope.enabled, "{change}");
            assert_eq!(callbacks, full_callbacks, "{change}");
            assert_eq!(account_graph_calls(&f.node) - before_graphs, 1, "{change}");
            let counts = take_sql_counts(&f.node.db);
            // Pinned SQLite 3.51.3 executes OP_Init before detecting the old
            // schema cookie after CREATE/DROP. sqlite3_step then reprepares,
            // resets and reruns that VM: RUN includes both attempts. The next
            // pass has no schema retry. Keep exact cold/warm expectations;
            // neither extra VM attempts nor REPREPARE are logical row reads.
            let (runs, reprepares) = if change == "reversed-ddl" && pass == 0 {
                ([3, 3, 0, 3, 2], [1, 1, 0, 1, 1])
            } else {
                ([2, 2, 0, 2, 1], [0; 5])
            };
            assert_eq!(counts.runs, runs, "{change} pass {pass}");
            assert_eq!(counts.reprepares, reprepares, "{change} pass {pass}");
            println!(
                "{}",
                serde_json::json!({
                    "change": change, "pass": pass,
                    "sqlite_vm_runs": counts.runs, "sqlite_reprepares": counts.reprepares,
                    "full_graph_calls": account_graph_calls(&f.node) - before_graphs,
                    "callbacks": callbacks, "original_full_callbacks": full_callbacks,
                    "history_hits": scope.history_hits, "reuse_enabled": scope.enabled,
                })
            );
        }
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn consumed_history_keeps_the_outer_last_write_fence() {
    let f = fixture();
    let mut scope = mint_genesis_history(&f.node);
    history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
        Ok(())
    })
    .unwrap();
    assert!(scope.consumed);
    assert_eq!(scope.history_hits, 1);
    f.node
        .db
        .execute("UPDATE snapshots SET state=state WHERE 0", [])
        .unwrap();
    let error = scope.validate_consumed(&f.node.db).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    let error = history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert_eq!(scope.history_hits, 1);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn history_early_and_final_errors_cannot_hide_transaction_replacement() {
    for sql in [
        "ROLLBACK; BEGIN IMMEDIATE",
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT history_probe; ROLLBACK TO history_probe; RELEASE history_probe",
    ] {
        for cancel_at in [1, 5] {
            let f = fixture();
            let mut scope = mint_genesis_history(&f.node);
            let mut current = 0;
            let error = history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
                current += 1;
                if current == cancel_at {
                    f.node.db.execute_batch(sql)?;
                    Err("HISTORY_READBACK_CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(
                error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"),
                "{sql}"
            );
            assert!(error.requires_owner_stop());
            assert_eq!(scope.history_hits, 0);
        }
    }
}

#[test]
fn foreign_initial_state_with_identical_context_cannot_borrow_history() {
    let (f, ids) = chain(2);
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[2]);
    history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
    let mut foreign = f.node.settings.clone();
    foreign
        .initial
        .insert("meta:foreign-history".into(), serde_json::json!(1));
    assert_eq!(foreign.network(), f.node.settings.network());
    assert_eq!(foreign.parameters(), f.node.settings.parameters());
    assert_eq!(foreign.genesis(), f.node.settings.genesis());
    let original = verify_history_with_cache(
        &f.node.db,
        &foreign,
        ids[2],
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap_err();
    let error = verify_history_with_readback(
        &f.node.db,
        &foreign,
        ids[2],
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
        Some(&mut scope),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), original.to_string());
    assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
    assert_eq!(scope.history_hits, 0);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn damaged_ancestors_genesis_and_graph_keep_original_errors_after_a_receipt() {
    let (f, ids) = chain(3);
    for change in ["record", "packet", "delta", "genesis", "graph"] {
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = capture(&f.node, ids[3]);
        // No earlier graph hit: invalidation must run the real verifier rather
        // than merely reject because another consumed result already existed.
        history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
        assert!(!scope.consumed);
        let changed = match change {
            "record" => f.node.db.execute(
                "UPDATE native_state_commitments SET data=x'00' WHERE block=?",
                [ids[1].as_slice()],
            ),
            "packet" => f.node.db.execute(
                "UPDATE blocks SET packet=x'00' WHERE id=?",
                [ids[1].as_slice()],
            ),
            "delta" => f.node.db.execute(
                "UPDATE deltas SET after=x'00' WHERE block=?",
                [ids[1].as_slice()],
            ),
            "genesis" => f.node.db.execute(
                "UPDATE snapshots SET state=x'00' WHERE block=?",
                [ids[0].as_slice()],
            ),
            "graph" => {
                let root = load_observed(&f.node.db, ids[0], None)
                    .unwrap()
                    .accounts
                    .node
                    .unwrap();
                f.node.db.execute(
                    "UPDATE archive_nodes SET data=x'00' WHERE id=?",
                    [root.as_slice()],
                )
            }
            _ => unreachable!(),
        }
        .unwrap();
        assert!(changed > 0, "{change}");
        let original = verify_history_with_cache(
            &f.node.db,
            &f.node.settings,
            ids[3],
            &mut || Ok(()),
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap_err();
        let error = history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), original.to_string(), "{change}");
        assert!(error.requires_owner_stop(), "{change}");
        assert_eq!(scope.history_hits, 0, "{change}");
        assert!(scope.histories.iter().all(Option::is_none), "{change}");
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn a_different_actual_connection_cannot_use_completed_history() {
    let f = fixture();
    let other = fixture();
    let mut scope = mint_genesis_history(&f.node);
    other.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = verify_history_with_readback(
        &other.node.db,
        &f.node.settings,
        f.node.settings.genesis(),
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
        Some(&mut scope),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
    assert_eq!(scope.history_hits, 0);
}

#[test]
fn completed_history_never_survives_rollback_or_cold_open() {
    let (mut f, ids) = chain(3);
    f.node.activate_observed(ids[3], 100_000).unwrap();
    let expected = f.node.state_at(ids[3]).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[3]);
    history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
    history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.history_hits, 1);
    f.node
        .db
        .execute_batch("ROLLBACK; BEGIN IMMEDIATE")
        .unwrap();
    let error = history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
    f.node.db.execute_batch("ROLLBACK").unwrap();
    drop(scope);

    let settings = f.node.settings.clone();
    drop(f.node);
    let node =
        Node::open_with_authenticated_state(f.directory.path(), settings.clone(), 1).unwrap();
    assert_eq!(node.state_at(ids[3]).unwrap(), expected);
    node.db.set_prepared_statement_cache_capacity(128);
    take_sql_counts(&node.db);
    verify_history_with_cache(
        &node.db,
        &node.settings,
        ids[3],
        &mut || Ok(()),
        Some(&node.authenticated_arithmetic),
    )
    .unwrap();
    assert_eq!(take_sql_counts(&node.db).runs, [8, 5, 3, 5, 1]);
    node.db
        .execute(
            "UPDATE snapshots SET state=x'00' WHERE block=?",
            [ids[0].as_slice()],
        )
        .unwrap();
    drop(node);
    assert!(Node::open_with_authenticated_state(f.directory.path(), settings, 1).is_err());
}
