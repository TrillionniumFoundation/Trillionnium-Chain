//! Completed-history bindings reused by the ordinary State verifier.
//! These controls measure complete SQLite work, including every scope/schema
//! fence, and retain the original current-State and final-callback checks.
use super::*;
use crate::store::native_authenticated::{verify_state_with_cache, verify_state_with_readback};

#[test]
fn state_binding_completed_receipt_reduces_all_sql_with_existing_fences() {
    let (f, ids) = chain(3);
    let states = [
        f.node.state_at(ids[2]).unwrap(),
        f.node.state_at(ids[3]).unwrap(),
    ];
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[3]);
    verify(&f.node, ids[3], &states[1], &mut scope, &mut || Ok(())).unwrap();
    history(&f.node, ids[3], &mut scope, &mut || Ok(())).unwrap();
    let foreign = f.node.settings.clone();
    for (block, state) in [ids[2], ids[3]].into_iter().zip(&states) {
        let record = load_observed(&f.node.db, block, None).unwrap();
        assert!(scope.completed_record_matches(&f.node.settings, &record));
        assert!(!scope.completed_record_matches(&foreign, &record));
        // An equal Settings clone retains all graph eligibility and fences,
        // but cannot borrow the original immutable Settings history receipt.
        take_sql_counts(&f.node.db);
        let mut previous_callbacks = 0;
        let previous_all = all_sql_progress_ticks(&f.node.db, || {
            verify_state_with_readback(
                &f.node.db,
                &foreign,
                block,
                state,
                &mut || {
                    previous_callbacks += 1;
                    Ok(())
                },
                Some(&f.node.authenticated_arithmetic),
                Some(&mut scope),
            )
        });
        let previous = take_sql_counts(&f.node.db);
        let mut current_callbacks = 0;
        let current_all = all_sql_progress_ticks(&f.node.db, || {
            verify(&f.node, block, state, &mut scope, &mut || {
                current_callbacks += 1;
                Ok(())
            })
        });
        let current = take_sql_counts(&f.node.db);
        assert_eq!(previous.runs, [2, 1, 1, 1, 0]);
        assert_eq!(current.runs, [1, 0, 0, 0, 0]);
        assert_eq!(previous_callbacks, 5);
        assert_eq!(current_callbacks, 2);
        assert!(current_all < previous_all);
        assert_eq!(previous.reprepares, [0; 5]);
        assert_eq!(current.reprepares, [0; 5]);
        assert!(scope.scope.same_write_snapshot(&f.node.db).unwrap());
        println!(
            "{}",
            serde_json::json!({
                "operation": "verify_state_with_readback",
                "height": record.height,
                "previous_material_vm_runs": previous.runs,
                "current_material_vm_runs": current.runs,
                "previous_all_sql_progress_ticks": previous_all,
                "current_all_sql_progress_ticks": current_all,
                "previous_callbacks": previous_callbacks,
                "current_callbacks": current_callbacks,
                "all_existing_scope_and_schema_fences": true,
                "transaction_trace_preserved": true,
                "qualification": "same-connection completed work only; not service TPS",
            })
        );
    }
    // Full History misses still run the original genesis State anchor checks.
    take_sql_counts(&f.node.db);
    verify(
        &f.node,
        ids[0],
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(take_sql_counts(&f.node.db).runs, [1, 1, 0, 1, 0]);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn state_binding_requires_completed_history_and_exact_record() {
    let (f, ids) = chain(2);
    let state = f.node.state_at(ids[2]).unwrap();
    for cancelled_history in [false, true] {
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = capture(&f.node, ids[2]);
        verify(&f.node, ids[2], &state, &mut scope, &mut || Ok(())).unwrap();
        if cancelled_history {
            let mut callbacks = 0;
            let error = history(&f.node, ids[2], &mut scope, &mut || {
                callbacks += 1;
                if callbacks == 2 {
                    Err("PUBLIC_REQUEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.code(), Some(crate::ErrorCode::PublicRequestCancelled));
        }
        assert!(scope.histories.iter().all(Option::is_none));
        take_sql_counts(&f.node.db);
        verify(&f.node, ids[2], &state, &mut scope, &mut || Ok(())).unwrap();
        assert_eq!(take_sql_counts(&f.node.db).runs, [2, 1, 1, 1, 0]);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[2]);
    history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
    let actual = load_observed(&f.node.db, ids[2], None).unwrap();
    for field in ["id", "parent", "packet", "height", "delta", "profile"] {
        let mut changed = actual.clone();
        match field {
            "id" => changed.id[0] ^= 1,
            "parent" => changed.parent_commitment.as_mut().unwrap()[0] ^= 1,
            "packet" => changed.packet_digest.as_mut().unwrap()[0] ^= 1,
            "height" => changed.height += 1,
            "delta" => changed.delta_root[0] ^= 1,
            "profile" => changed.state.parameters[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            !scope.completed_record_matches(&f.node.settings, &changed),
            "{field}"
        );
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn state_binding_keeps_current_state_and_final_scope_checks() {
    let (f, ids) = chain(2);
    let state = f.node.state_at(ids[2]).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, ids[2]);
    history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
    let owner = format!(
        "account:{}",
        hex::encode(crate::development_public(0).unwrap())
    );
    for change in ["nonce", "balance", "working", "missing-account", "field"] {
        let mut changed = state.clone();
        match change {
            "nonce" => changed.get_mut(&owner).unwrap()["nonce"] = serde_json::json!(1),
            "balance" => {
                let balance = changed[&owner]["balance"].as_u64().unwrap();
                changed.get_mut(&owner).unwrap()["balance"] = serde_json::json!(balance - 1);
            }
            "working" => {
                changed.insert("meta:state-binding".into(), serde_json::json!(1));
            }
            "missing-account" => {
                changed.remove(&owner);
            }
            "field" => changed.get_mut(&owner).unwrap()["extra"] = serde_json::json!(0),
            _ => unreachable!(),
        }
        let original = verify_state_with_cache(
            &f.node.db,
            &f.node.settings,
            ids[2],
            &changed,
            &mut || Ok(()),
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap_err();
        let error = verify(&f.node, ids[2], &changed, &mut scope, &mut || Ok(())).unwrap_err();
        assert_eq!(
            error_signature(&error),
            error_signature(&original),
            "{change}"
        );
        assert!(!scope.consumed);
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();

    // Exercise both existing final fence branches: a graph hit and a complete
    // real SQL graph traversal when no graph receipt/frontier is retained.
    for retain_graph in [false, true] {
        for sql in [
            "UPDATE blocks SET packet=NULL WHERE id=?",
            "UPDATE deltas SET after=x'00' WHERE block=?",
            "UPDATE snapshots SET state=state WHERE 0",
            "PRAGMA writable_schema=ON",
        ] {
            f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut scope = capture(&f.node, ids[2]);
            history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
            if !retain_graph {
                scope.graphs = [None, None, None, None];
                scope.frontier = None;
            }
            let mut total_callbacks = 0;
            verify(&f.node, ids[2], &state, &mut scope, &mut || {
                total_callbacks += 1;
                Ok(())
            })
            .unwrap();
            // This successful use deliberately consumes the material receipt.
            assert!(scope.consumed);
            if !retain_graph {
                scope.graphs = [None, None, None, None];
                scope.frontier = None;
            }
            let mut callbacks = 0;
            let error = verify(&f.node, ids[2], &state, &mut scope, &mut || {
                callbacks += 1;
                if callbacks == total_callbacks {
                    if sql.contains('?') {
                        assert!(f.node.db.execute(sql, [ids[2].as_slice()])? > 0);
                    } else {
                        f.node.db.execute_batch(sql)?;
                    }
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(
                callbacks, total_callbacks,
                "{sql} retain_graph={retain_graph}"
            );
            assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
            assert!(error.requires_owner_stop());
            assert!(scope.histories.iter().all(Option::is_none));
            f.node
                .db
                .execute_batch("ROLLBACK; PRAGMA writable_schema=OFF")
                .unwrap();
        }
    }
}

#[test]
fn state_binding_final_cancellation_preserves_typed_cause_and_replaced_scope() {
    let (f, ids) = chain(2);
    let state = f.node.state_at(ids[2]).unwrap();
    for sql in [
        "UPDATE snapshots SET state=state WHERE 0",
        "ROLLBACK; BEGIN IMMEDIATE",
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT state_probe; ROLLBACK TO state_probe; RELEASE state_probe",
    ] {
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = capture(&f.node, ids[2]);
        history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
        let mut callbacks = 0;
        let error = verify(&f.node, ids[2], &state, &mut scope, &mut || {
            callbacks += 1;
            if callbacks == 2 {
                f.node.db.execute_batch(sql)?;
                Err("PUBLIC_REQUEST_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        let expected = scope
            .finish::<()>(Err("PUBLIC_REQUEST_CANCELLED".into()))
            .unwrap_err();
        assert_eq!(error_signature(&error), error_signature(&expected), "{sql}");
        let cancellation = if sql.starts_with("UPDATE") {
            &error
        } else {
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
        };
        assert!(cancellation.is(crate::ErrorCode::PublicRequestCancelled));
        assert_eq!(callbacks, 2);
        assert!(!scope.consumed);
        assert_eq!(error.requires_owner_stop(), !sql.starts_with("UPDATE"));
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn state_binding_unconsumed_final_write_revalidates_without_old_receipts() {
    let (f, ids) = chain(2);
    let state = f.node.state_at(ids[2]).unwrap();
    for sql in [
        "UPDATE blocks SET packet=NULL WHERE id=?",
        "UPDATE blocks SET packet=packet WHERE id=?",
    ] {
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        // Determine the final callback of the actual complete SQL graph walk.
        // Clearing a receipt only removes reuse; it cannot fabricate proof.
        let mut measured = capture(&f.node, ids[2]);
        history(&f.node, ids[2], &mut measured, &mut || Ok(())).unwrap();
        measured.graphs = [None, None, None, None];
        measured.frontier = None;
        let before_graphs = account_graph_calls(&f.node);
        let mut final_callback = 0;
        take_sql_counts(&f.node.db);
        verify(&f.node, ids[2], &state, &mut measured, &mut || {
            final_callback += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(account_graph_calls(&f.node) - before_graphs, 1);
        assert_eq!(take_sql_counts(&f.node.db).runs, [1, 0, 0, 0, 0]);
        assert!(final_callback > 2);
        assert!(measured.consumed);
        drop(measured);

        // This independently completed history has never been consumed.
        let mut scope = capture(&f.node, ids[2]);
        history(&f.node, ids[2], &mut scope, &mut || Ok(())).unwrap();
        scope.graphs = [None, None, None, None];
        scope.frontier = None;
        assert!(!scope.consumed);
        let mut callbacks = 0;
        let result = verify(&f.node, ids[2], &state, &mut scope, &mut || {
            callbacks += 1;
            if callbacks == final_callback {
                assert_eq!(f.node.db.execute(sql, [ids[2].as_slice()])?, 1);
            }
            Ok(())
        });
        assert!(callbacks > final_callback);
        let original = verify_state_with_cache(
            &f.node.db,
            &f.node.settings,
            ids[2],
            &state,
            &mut || Ok(()),
            Some(&f.node.authenticated_arithmetic),
        );
        match (result, original) {
            (Ok(()), Ok(())) => assert!(sql.contains("packet=packet")),
            (Err(error), Err(original)) => {
                assert!(sql.contains("packet=NULL"));
                assert_eq!(error.to_string(), "NATIVE_STATE_PACKET");
                assert_eq!(error_signature(&error), error_signature(&original));
            }
            pair => panic!("scoped result diverged from original verifier: {pair:?}"),
        }
        assert!(!scope.enabled);
        assert!(!scope.consumed);
        assert!(scope.graphs.iter().all(Option::is_none));
        assert!(scope.histories.iter().all(Option::is_none));
        assert!(scope.frontier.is_none());

        // Disabled scopes cannot hand their old material or graph to a later
        // caller, including after the benign write returned the correct State.
        take_sql_counts(&f.node.db);
        let again = verify(&f.node, ids[2], &state, &mut scope, &mut || Ok(()));
        assert_eq!(again.is_ok(), sql.contains("packet=packet"));
        let counts = take_sql_counts(&f.node.db);
        assert!(counts.runs[1] > 0);
        assert!(!scope.consumed);
        assert!(scope.histories.iter().all(Option::is_none));
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}
