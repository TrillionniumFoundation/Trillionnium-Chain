//! Deterministic schedule and actual-SQL controls. Stub resource callbacks in
//! these unit cases do not qualify the separate physical-kernel native gate.
use super::*;
use crate::account_archive_prototype::native_store::{self, graph_point_for_test, LiftCache};
use crate::{ErrorCode, ErrorKind};
use rusqlite::Connection;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::hash;

fn point(kind: AccountGraphKind) -> NativeProgressPoint {
    NativeProgressPoint::AccountGraph(graph_point_for_test(kind))
}

#[test]
fn graph_resource_v1_keeps_every_cpu_point_and_exact_eight_body_limit() {
    for nodes in [0, 1, 7, 8, 9, 15, 16, 17, 31] {
        let cpu_calls = Cell::new(0u64);
        let full_calls = AtomicU64::new(0);
        let cpu = || {
            cpu_calls.set(cpu_calls.get() + 1);
            Ok(())
        };
        let full = || {
            full_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let counters = SharedCounters::default();
        let mut progress = GraphProgress::new(&cpu, &full, Arc::clone(&counters));
        progress.point(point(AccountGraphKind::Enter)).unwrap();
        let mut bodies = 0;
        for ordinal in 0..nodes {
            progress
                .point(point(AccountGraphKind::BeforeNode { ordinal }))
                .unwrap();
            bodies += 1;
        }
        progress
            .point(point(AccountGraphKind::BeforeFinalRelation {
                completed: bodies,
            }))
            .unwrap();
        progress
            .point(point(AccountGraphKind::Exit {
                completed: bodies,
                succeeded: true,
            }))
            .unwrap();
        progress.complete().unwrap();
        assert_eq!(bodies, nodes);
        assert_eq!(cpu_calls.get(), u64::from(nodes) + 3);
        assert_eq!(
            full_calls.load(Ordering::SeqCst),
            3 + u64::from(nodes.div_ceil(8))
        );
        let counters = counters.lock().unwrap();
        assert_eq!(counters.graph_node_checkpoints, u64::from(nodes));
        assert_eq!(counters.graph_completed_node_bodies, u64::from(nodes));
        assert!(counters.graph_max_node_window <= 8);
        assert_eq!(counters.graph_entries, counters.graph_exits);
        assert_eq!(counters.scope_failures + counters.unfinished_scopes, 0);
    }
}

#[test]
fn graph_resource_v1_cancels_every_node_inside_kernel_read_windows() {
    for cancelled_node in 0..18 {
        let cancelled = Cell::new(false);
        let cpu = || ensure(!cancelled.get(), "PUBLIC_REQUEST_CANCELLED");
        let full_calls = AtomicU64::new(0);
        let full = || {
            full_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let counters = SharedCounters::default();
        let mut progress = GraphProgress::new(&cpu, &full, Arc::clone(&counters));
        progress.point(point(AccountGraphKind::Enter)).unwrap();
        for ordinal in 0..cancelled_node {
            progress
                .point(point(AccountGraphKind::BeforeNode { ordinal }))
                .unwrap();
        }
        cancelled.set(true);
        let error = progress
            .point(point(AccountGraphKind::BeforeNode {
                ordinal: cancelled_node,
            }))
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        let before_exit = full_calls.load(Ordering::SeqCst);
        assert!(progress
            .point(point(AccountGraphKind::Exit {
                completed: cancelled_node,
                succeeded: false
            }))
            .is_err());
        assert_eq!(
            full_calls.load(Ordering::SeqCst),
            before_exit + 1,
            "failed CPU does not erase the full Exit fence"
        );
        assert!(progress.complete().is_err());
        let counters = counters.lock().unwrap();
        assert_eq!(
            counters.graph_completed_node_bodies,
            u64::from(cancelled_node)
        );
        assert_eq!(counters.graph_aborts, 1);
        assert!(counters.graph_max_node_window <= 8);
    }
}

#[test]
fn graph_resource_v1_rejects_forged_order_nested_and_unfinished_scopes() {
    use AccountGraphKind::*;
    for sequence in [
        vec![BeforeNode { ordinal: 0 }],
        vec![Enter, BeforeNode { ordinal: 1 }],
        vec![Enter, BeforeNode { ordinal: 0 }, BeforeNode { ordinal: 0 }],
        vec![Enter, BeforeNode { ordinal: 131_071 }],
        vec![Enter, Enter],
        vec![Enter, BeforeFinalRelation { completed: 1 }],
        vec![
            Enter,
            BeforeNode { ordinal: 0 },
            BeforeFinalRelation { completed: 0 },
        ],
        vec![
            Enter,
            BeforeFinalRelation { completed: 0 },
            BeforeNode { ordinal: 0 },
        ],
        vec![
            Enter,
            Exit {
                completed: 0,
                succeeded: true,
            },
        ],
        vec![Exit {
            completed: 0,
            succeeded: false,
        }],
    ] {
        let counters = SharedCounters::default();
        let mut progress = GraphProgress::new(&|| Ok(()), &|| Ok(()), counters);
        let result = sequence
            .into_iter()
            .try_for_each(|kind| progress.point(point(kind)));
        let error = result.unwrap_err();
        assert!(error.is(ErrorCode::HistoryGraphResourceScopeV1));
        assert_eq!(error.kind(), ErrorKind::LocalStructure);
        assert!(progress.complete().is_err());
    }
    let counters = SharedCounters::default();
    {
        let mut progress = GraphProgress::new(&|| Ok(()), &|| Ok(()), Arc::clone(&counters));
        progress.point(point(Enter)).unwrap();
        assert!(progress.complete().is_err());
    }
    assert_eq!(counters.lock().unwrap().unfinished_scopes, 1);
}

#[test]
fn graph_resource_v1_actual_empty_graph_entry_final_and_exit_refusals_never_qualify() {
    for fail_at in 1..=3 {
        let calls = AtomicU64::new(0);
        let full = || {
            let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
            ensure(call != fail_at, "PUBLIC_HOST_KERNEL_LIMITS_CHANGED")
        };
        let counters = SharedCounters::default();
        let mut progress = GraphProgress::new(&|| Ok(()), &full, Arc::clone(&counters));
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(crate::store::native_authenticated::DDL)
            .unwrap();
        let root = native_store::seed(&db, &State::new(), &mut || Ok(())).unwrap();
        let error = native_store::verify_with_lifts_native_progress(
            &db,
            &root,
            &State::new(),
            &mut progress,
            None,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "PUBLIC_HOST_KERNEL_LIMITS_CHANGED");
        assert_ne!(error.kind(), ErrorKind::ProtocolInvalid);
        assert!(
            progress.complete().is_err(),
            "no failed Enter, final relation or Exit can qualify this scope"
        );
        assert!(counters.lock().unwrap().graph_node_checkpoints == 0);
        assert_eq!(counters.lock().unwrap().graph_exits, 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if fail_at == 1 { 2 } else { 3 }
        );
    }
}

#[test]
fn graph_resource_v1_ignored_resource_refusal_cannot_be_reused_as_success() {
    let calls = AtomicU64::new(0);
    let full = || {
        ensure(
            calls.fetch_add(1, Ordering::SeqCst) != 0,
            "PUBLIC_HOST_KERNEL_LIMITS_CHANGED",
        )
    };
    let counters = SharedCounters::default();
    let mut progress = GraphProgress::new(&|| Ok(()), &full, Arc::clone(&counters));
    assert!(progress.point(point(AccountGraphKind::Enter)).is_err());
    assert!(progress
        .point(point(AccountGraphKind::Exit {
            completed: 0,
            succeeded: false
        }))
        .is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "abort still attempts current complete resource check"
    );
    assert!(progress.complete().is_err());
    assert!(progress.point(NativeProgressPoint::BeforeCommit).is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "commit check is neither cached nor omitted"
    );
}

fn corrupt_current_rows(typed: bool) -> (String, ErrorKind, u64) {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let state: State = (0..32u64)
        .map(|i| {
            let owner = hash(
                b"graph-resource-current-row-control-v1",
                &[&i.to_le_bytes()],
            );
            (
                format!("account:{}", hex::encode(owner)),
                serde_json::json!({"balance":i + 1,"nonce":i}),
            )
        })
        .collect();
    let root = native_store::seed(&db, &state, &mut || Ok(())).unwrap();
    let cache = LiftCache::default();
    native_store::verify_with_lifts(&db, &root, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let calls = Cell::new(0u64);
    let changed = Cell::new(false);
    let cpu = || {
        calls.set(calls.get() + 1);
        // Enter is an additional typed CPU boundary. Both arms mutate at the
        // original node ordinal1, inside the N8 window after the root's reads.
        if calls.get() == if typed { 3 } else { 2 } {
            assert!(
                db.execute(
                    "UPDATE archive_nodes SET data=zeroblob(1) WHERE id!=?1",
                    [root.node.unwrap().as_slice()]
                )? > 0
            );
            changed.set(true);
        }
        Ok(())
    };
    let counters = SharedCounters::default();
    let result = if typed {
        let mut progress = GraphProgress::new(&cpu, &|| Ok(()), Arc::clone(&counters));
        native_store::verify_with_lifts_native_progress(
            &db,
            &root,
            &state,
            &mut progress,
            Some(&cache),
        )
    } else {
        native_store::verify_with_lifts(&db, &root, &state, &mut || cpu(), Some(&cache))
    };
    assert!(changed.get());
    let error = result.unwrap_err();
    let nodes = counters.lock().unwrap().graph_node_checkpoints;
    (error.to_string(), error.kind(), nodes)
}

#[test]
fn graph_resource_v1_reads_current_sql_on_non_full_nodes_with_warm_arithmetic() {
    let strict = corrupt_current_rows(false);
    let bounded = corrupt_current_rows(true);
    assert_eq!((&strict.0, strict.1), (&bounded.0, bounded.1));
    assert_eq!(bounded.1, ErrorKind::LocalStructure);
    assert_eq!(
        bounded.2, 2,
        "the actual unread child is checked at node1, not deferred to a resource fence"
    );
}
