//! Exact completed-history start bindings, including the original error order.
//! Aggregate SQLite progress ticks include uncached fences/PRAGMAs without
//! replacing the transaction observer's trace hook. They are not service TPS.
use super::super::super::verify_record;
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// The successful completed-hit path before start-binding reuse, taken from
// 97aaf's verify_history_with_readback. This is a measurement reference only;
// full misses and failure ordering use the original full verifier below.
fn previous_completed_hit(
    node: &Node,
    block: Hash,
    scope: &mut PostWriteReadback<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let result = (|| {
        progress()?;
        let record = load_observed(
            &node.db,
            block,
            Some((&node.settings, &node.authenticated_arithmetic)),
        )?;
        verify_record(
            &node.db,
            &node.settings,
            &record,
            progress,
            Some(&node.authenticated_arithmetic),
        )?;
        assert!(scope.history_matches(&node.db, &node.settings, &record)?);
        progress()?;
        assert!(scope.history_matches(&node.db, &node.settings, &record)?);
        scope.consumed = true;
        scope.history_hits += 1;
        Ok(())
    })();
    scope.finish(result)
}

fn all_sql_progress_ticks(db: &Connection, run: impl FnOnce() -> Result<()>) -> u64 {
    let ticks = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&ticks);
    db.progress_handler(
        1,
        Some(move || {
            observed.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    let result = run();
    db.progress_handler(0, None::<fn() -> bool>).unwrap();
    result.unwrap();
    ticks.load(Ordering::Relaxed)
}

fn error_signature(error: &Error) -> (String, String, bool, Vec<String>) {
    let mut chain = Vec::new();
    let mut current: Option<&dyn std::error::Error> = Some(error);
    while let Some(error) = current {
        chain.push(error.to_string());
        current = error.source();
    }
    (
        format!("{:?}", error.code()),
        format!("{:?}", error.kind()),
        error.requires_owner_stop(),
        chain,
    )
}

#[test]
fn exact_completed_record_reduces_material_and_whole_sql_work() {
    let (f, ids) = chain(3);
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[3]);
    history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
    for block in [ids[0], ids[3]] {
        let record = load_observed(&f.node.db, block, None).unwrap();
        assert!(record.delta_count < 256);
        take_sql_counts(&f.node.db);
        let mut previous_callbacks = 0;
        let previous_all = all_sql_progress_ticks(&f.node.db, || {
            previous_completed_hit(&f.node, block, &mut scope, &mut || {
                previous_callbacks += 1;
                Ok(())
            })
        });
        let previous = take_sql_counts(&f.node.db);
        let mut current_callbacks = 0;
        let current_all = all_sql_progress_ticks(&f.node.db, || {
            history(&f.node, block, &mut scope, &mut || {
                current_callbacks += 1;
                Ok(())
            })
        });
        let current = take_sql_counts(&f.node.db);
        assert_eq!(
            previous.runs,
            if record.parent.is_some() {
                [2, 1, 1, 1, 0]
            } else {
                [1, 1, 0, 1, 0]
            }
        );
        assert_eq!(current.runs, [1, 0, 0, 0, 0]);
        assert_eq!(previous.reprepares, [0; 5]);
        assert_eq!(current.reprepares, [0; 5]);
        assert_eq!(previous_callbacks, 5);
        assert_eq!(current_callbacks, 2);
        assert!(current.steps.iter().sum::<i32>() < previous.steps.iter().sum::<i32>());
        // The material saving must survive ALL SQL work, including both
        // unchanged-scope fences, fresh schema queries and finish's probe.
        assert!(current_all < previous_all);
        assert!(scope.scope.same_write_snapshot(&f.node.db).unwrap());
        println!(
            "{}",
            serde_json::json!({
                "height": record.height,
                "delta_count": record.delta_count,
                "sql_order": ["record", "block", "parent", "delta", "genesis_snapshot"],
                "previous_material_vm_runs": previous.runs,
                "current_material_vm_runs": current.runs,
                "previous_material_vm_steps": previous.steps,
                "current_material_vm_steps": current.steps,
                "previous_all_sql_progress_ticks": previous_all,
                "current_all_sql_progress_ticks": current_all,
                "progress_counter_scope": "SQLite progress handler interval1; includes all SQL and any prepare work SQLite reports, not a statement or row count",
                "previous_callbacks": previous_callbacks,
                "current_callbacks": current_callbacks,
                "transaction_trace_preserved": true,
                "qualification": "same-connection work comparison only; not throughput or activation qualification",
            })
        );
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn graph_receipts_never_authorize_start_record_binding() {
    let (f, ids) = chain(2);
    let state = f.node.state_at(ids[2]).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    // The child graph can be verified without validating the genesis block's
    // packet column. Make the corrupt bytes precede this scope's write epoch.
    f.node
        .db
        .execute(
            "UPDATE blocks SET packet=x'00' WHERE id=?",
            [ids[0].as_slice()],
        )
        .unwrap();
    let mut scope = capture(&f.node, ids[2]);
    verify(&f.node, ids[2], &state, &mut scope, &mut || Ok(())).unwrap();
    let genesis = load_observed(&f.node.db, ids[0], None).unwrap();
    assert!(scope
        .graphs
        .iter()
        .flatten()
        .any(|record| record.accounts == genesis.accounts));
    assert!(scope.histories.iter().all(Option::is_none));
    take_sql_counts(&f.node.db);
    let error = history(&f.node, ids[0], &mut scope, &mut || Ok(())).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
    assert!(error.requires_owner_stop());
    assert_eq!(take_sql_counts(&f.node.db).runs, [1, 1, 0, 0, 0]);
    assert_eq!(scope.history_hits, 0);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn unchanged_record_requires_actual_material_after_any_write() {
    let (f, ids) = chain(3);
    for consumed in [false, true] {
        for change in [
            "packet-null",
            "packet-bytes",
            "packet-type",
            "work",
            "state-root",
            "parent-height",
            "parent-work",
            "parent-record",
            "delta",
        ] {
            f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut scope = capture(&f.node, ids[3]);
            history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
            assert!(!scope.consumed);
            if consumed {
                history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
            }
            let before = load_observed(&f.node.db, ids[3], None).unwrap();
            let (sql, block) = match change {
                "packet-null" => ("UPDATE blocks SET packet=NULL WHERE id=?", ids[3]),
                "packet-bytes" => ("UPDATE blocks SET packet=x'00' WHERE id=?", ids[3]),
                "packet-type" => ("UPDATE blocks SET packet='wrong-type' WHERE id=?", ids[3]),
                "work" => ("UPDATE blocks SET chainwork=x'00' WHERE id=?", ids[3]),
                "state-root" => ("UPDATE blocks SET state_root=x'00' WHERE id=?", ids[3]),
                "parent-height" => ("UPDATE blocks SET height=height+1 WHERE id=?", ids[2]),
                "parent-work" => ("UPDATE blocks SET chainwork=x'00' WHERE id=?", ids[2]),
                "parent-record" => (
                    "UPDATE native_state_commitments SET data=x'00' WHERE block=?",
                    ids[2],
                ),
                "delta" => ("UPDATE deltas SET after=x'00' WHERE block=?", ids[3]),
                _ => unreachable!(),
            };
            assert!(f.node.db.execute(sql, [block.as_slice()]).unwrap() > 0);
            assert_eq!(load_observed(&f.node.db, ids[3], None).unwrap(), before);
            let original = verify_history_with_cache(
                &f.node.db,
                &f.node.settings,
                ids[3],
                &mut || Ok(()),
                Some(&f.node.authenticated_arithmetic),
            )
            .unwrap_err();
            let error = history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap_err();
            assert_eq!(
                error_signature(&error),
                error_signature(&original),
                "{change} consumed={consumed}"
            );
            assert!(error.requires_owner_stop(), "{change}");
            assert_eq!(scope.history_hits, usize::from(consumed));
            assert!(!scope.enabled);
            assert!(scope.histories.iter().all(Option::is_none));
            f.node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn a_probe_error_survives_cleared_history_receipts() {
    for change in ["no-row", "prepare-only"] {
        let f = fixture();
        let mut scope = mint_genesis_history(&f.node);
        history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
            Ok(())
        })
        .unwrap();
        assert!(scope.consumed);
        match change {
            "no-row" => {
                f.node
                    .db
                    .execute("UPDATE snapshots SET state=state WHERE 0", [])
                    .unwrap();
            }
            "prepare-only" => {
                drop(f.node.db.prepare("PRAGMA writable_schema=ON").unwrap());
            }
            _ => unreachable!(),
        }
        let mut callbacks = 0;
        let error = history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
        assert!(error.requires_owner_stop());
        // Entry and the original current-delta traversal run before returning
        // the deferred error at the original first history fence, not later.
        assert_eq!(callbacks, 4);
        assert!(scope.histories.iter().all(Option::is_none));
        assert!(!scope.enabled);
        assert_eq!(scope.history_hits, 1);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn transaction_replacement_preserves_original_material_error_sources() {
    let (f, ids) = chain(2);
    for sql in [
        "ROLLBACK; BEGIN IMMEDIATE",
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT history_probe; ROLLBACK TO history_probe; RELEASE history_probe",
    ] {
        for consumed in [false, true] {
            f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut scope = capture(&f.node, ids[2]);
            history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
            if consumed {
                history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
            }
            f.node.db.execute_batch(sql).unwrap();
            f.node
                .db
                .execute(
                    "UPDATE blocks SET packet=NULL WHERE id=?",
                    [ids[2].as_slice()],
                )
                .unwrap();
            let material_error = verify_history_with_cache(
                &f.node.db,
                &f.node.settings,
                ids[2],
                &mut || Ok(()),
                Some(&f.node.authenticated_arithmetic),
            )
            .unwrap_err();
            assert_eq!(material_error.to_string(), "NATIVE_STATE_PACKET");
            let original = scope.finish::<()>(Err(material_error)).unwrap_err();
            let error = history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap_err();
            assert_eq!(error_signature(&error), error_signature(&original), "{sql}");
            assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
            assert!(error.requires_owner_stop());
            assert_eq!(scope.history_hits, usize::from(consumed));
            f.node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn final_callback_writes_revalidate_or_refuse_original_scope() {
    let (f, ids) = chain(2);
    for consumed in [false, true] {
        for sql in [
            "UPDATE blocks SET packet=NULL WHERE id=?",
            "UPDATE deltas SET after=x'00' WHERE block=?",
        ] {
            f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut scope = capture(&f.node, ids[2]);
            history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
            if consumed {
                history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
            }
            let mut callbacks = 0;
            let error = history(&f.node, ids[2], &mut scope, &mut || {
                callbacks += 1;
                if callbacks == 2 {
                    assert!(f.node.db.execute(sql, [ids[2].as_slice()])? > 0);
                }
                Ok(())
            })
            .unwrap_err();
            if consumed {
                assert_eq!(callbacks, 2);
                assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
            } else {
                assert!(callbacks > 2);
                let original = verify_history_with_cache(
                    &f.node.db,
                    &f.node.settings,
                    ids[2],
                    &mut || Ok(()),
                    Some(&f.node.authenticated_arithmetic),
                )
                .unwrap_err();
                assert_eq!(error_signature(&error), error_signature(&original));
            }
            assert!(error.requires_owner_stop());
            assert_eq!(scope.history_hits, usize::from(consumed));
            assert!(!scope.enabled);
            assert!(scope.histories.iter().all(Option::is_none));
            f.node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn final_callback_cancellation_keeps_ordinary_error_and_aba_source() {
    for sql in [
        "UPDATE snapshots SET state=state WHERE 0",
        "ROLLBACK; BEGIN IMMEDIATE",
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT history_probe; ROLLBACK TO history_probe; RELEASE history_probe",
    ] {
        let f = fixture();
        let mut scope = mint_genesis_history(&f.node);
        let mut callbacks = 0;
        let error = history(&f.node, f.node.settings.genesis(), &mut scope, &mut || {
            callbacks += 1;
            if callbacks == 2 {
                f.node.db.execute_batch(sql)?;
                return Err("HISTORY_RECORD_CANCELLED".into());
            }
            Ok(())
        })
        .unwrap_err();
        let expected = scope
            .finish::<()>(Err("HISTORY_RECORD_CANCELLED".into()))
            .unwrap_err();
        assert_eq!(error_signature(&error), error_signature(&expected), "{sql}");
        assert_eq!(callbacks, 2);
        assert_eq!(scope.history_hits, 0);
        assert!(!scope.consumed);
        if sql.starts_with("UPDATE") {
            assert_eq!(error.to_string(), "HISTORY_RECORD_CANCELLED");
            assert!(!error.requires_owner_stop());
            assert!(!scope.current(&f.node.db).unwrap());
        } else {
            assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
            assert!(error.requires_owner_stop());
        }
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn exact_settings_and_record_membership_keep_fifth_records_on_full_walk() {
    let (f, ids) = chain(4);
    let state = f.node.state_at(ids[4]).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[4]);
    verify(&f.node, ids[4], &state, &mut scope, &mut || Ok(())).unwrap();
    history(&f.node, ids[4], &mut scope, &mut || Ok(())).unwrap();
    assert!(!scope.ids.contains(&Some(ids[2])));
    let actual = load_observed(&f.node.db, ids[4], None).unwrap();
    for field in ["id", "parent", "packet", "height", "delta", "state"] {
        let mut changed = actual.clone();
        match field {
            "id" => changed.id[0] ^= 1,
            "parent" => changed.parent_commitment.as_mut().unwrap()[0] ^= 1,
            "packet" => changed.packet_digest.as_mut().unwrap()[0] ^= 1,
            "height" => changed.height += 1,
            "delta" => changed.delta_root[0] ^= 1,
            "state" => changed.state.parameters[0] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(changed.accounts, actual.accounts);
        assert!(!scope
            .history_matches(&f.node.db, &f.node.settings, &changed)
            .unwrap());
    }
    let foreign = f.node.settings.clone();
    take_sql_counts(&f.node.db);
    verify_history_with_readback(
        &f.node.db,
        &foreign,
        ids[4],
        &mut || Ok(()),
        Some(&f.node.authenticated_arithmetic),
        Some(&mut scope),
    )
    .unwrap();
    assert_eq!(take_sql_counts(&f.node.db).runs, [10, 6, 4, 6, 1]);
    assert_eq!(scope.history_hits, 0);
    history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(take_sql_counts(&f.node.db).runs, [6, 4, 2, 4, 1]);
    assert_eq!(scope.history_hits, 0);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn cancelled_full_walk_cannot_publish_a_start_record_proof() {
    let (f, ids) = chain(3);
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[3]);
    let mut callbacks = 0;
    let error = history(&f.node, ids[3], &mut scope, &mut || {
        callbacks += 1;
        if callbacks == 5 {
            Err("HISTORY_RECORD_CANCELLED".into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "HISTORY_RECORD_CANCELLED");
    assert!(scope.histories.iter().all(Option::is_none));
    assert!(!scope.consumed);
    take_sql_counts(&f.node.db);
    history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(take_sql_counts(&f.node.db).runs, [8, 5, 3, 5, 1]);
    assert_eq!(scope.history_hits, 0);
    assert!(scope.histories.iter().any(Option::is_some));
    f.node.db.execute_batch("ROLLBACK").unwrap();
}
