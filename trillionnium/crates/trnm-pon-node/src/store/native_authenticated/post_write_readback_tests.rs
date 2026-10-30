//! Actual SQLite/Node controls for the transaction-local graph readback.
//! These are functional controls, not throughput or resource-budget evidence.
use super::*;
use crate::account_archive_prototype::native_store::AccountGraphKind;
use crate::native_progress::{NativeProgressPoint, TypedNativeProgress};
use crate::{ErrorCode, Node};
use std::cell::Cell;

struct Fixture {
    node: Node,
    _directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    Fixture {
        node,
        _directory: directory,
    }
}

fn start(node: &Node, child: Hash) -> PostWriteReadback<'_> {
    assert!(!node.db.is_autocommit());
    let owner = TransactionScope::capture(&node.db).unwrap();
    PostWriteReadback::new(
        &node.db,
        &node.settings,
        child,
        &owner,
        node.post_write_schema
            .as_ref()
            .expect("ordinary writer source schema"),
    )
    .unwrap()
    .expect("actual ordinary-table main writer qualifies")
}

#[derive(Default)]
struct Counts {
    boundaries: usize,
    enters: usize,
    nodes: usize,
    exits: usize,
}

impl NativeProgress for Counts {
    fn checkpoint(&mut self) -> Result<()> {
        self.boundaries += 1;
        Ok(())
    }
    fn account_graph(&mut self, point: native_store::AccountGraphPoint) -> Result<()> {
        match point.kind() {
            AccountGraphKind::Enter => self.enters += 1,
            AccountGraphKind::BeforeNode { .. } => self.nodes += 1,
            AccountGraphKind::Exit { .. } => self.exits += 1,
            AccountGraphKind::BeforeFinalRelation { .. } => {}
        }
        Ok(())
    }
}

fn verify(
    node: &Node,
    block: Hash,
    state: &State,
    readback: &mut PostWriteReadback<'_>,
    progress: &mut dyn NativeProgress,
) -> Result<()> {
    verify_state_with_readback(
        &node.db,
        &node.settings,
        block,
        state,
        progress,
        Some(&node.authenticated_arithmetic),
        Some(readback),
    )
}

fn mint_genesis<'db>(node: &'db Node, counts: &mut Counts) -> PostWriteReadback<'db> {
    let genesis = node.settings.genesis();
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut readback = start(node, genesis);
    verify(node, genesis, &node.settings.initial, &mut readback, counts).unwrap();
    assert_eq!(counts.enters, 1);
    assert_eq!(counts.exits, 1);
    assert!(counts.nodes > 0, "a real account graph was traversed");
    assert!(readback.graphs[0].is_some());
    assert_eq!(readback.hits, 0);
    readback
}

#[test]
fn actual_child_and_genesis_reuse_preserves_full_state_and_original_readback() {
    let mut f = fixture();
    let genesis = f.node.settings.genesis();
    let packet = f
        .node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let child = f.node.admit(&packet, 100_000).unwrap();
    let state = f.node.state_at(child).unwrap();
    let before_active = f.node.read_active().unwrap();
    let before_record = load_observed(&f.node.db, child, None).unwrap();
    let before_deltas = deltas(&f.node.db, child).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let before_changes = f.node.db.total_changes();
    let mut readback = start(&f.node, child);
    let mut counts = Counts::default();
    verify(&f.node, child, &state, &mut readback, &mut counts).unwrap();
    verify_history_with_readback(
        &f.node.db,
        &f.node.settings,
        child,
        &mut counts,
        Some(&f.node.authenticated_arithmetic),
        Some(&mut readback),
    )
    .unwrap();
    assert_eq!(counts.enters, 2);
    assert!(readback.graphs.iter().all(Option::is_some));
    let boundaries = counts.boundaries;
    let actual_child = f
        .node
        .state_at_with_post_write_readback(child, &mut counts, &mut readback)
        .unwrap();
    verify_history_with_readback(
        &f.node.db,
        &f.node.settings,
        child,
        &mut counts,
        Some(&f.node.authenticated_arithmetic),
        Some(&mut readback),
    )
    .unwrap();
    assert_eq!(actual_child, state);
    assert_eq!(
        counts.enters, 2,
        "no synthetic or repeated graph walk on the hits"
    );
    assert_eq!(readback.hits, 2);
    assert!(
        counts.boundaries > boundaries,
        "original boundary callbacks still execute"
    );
    let mut original_counts = Counts::default();
    verify_state_with_native_progress(
        &f.node.db,
        &f.node.settings,
        child,
        &state,
        &mut original_counts,
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    assert_eq!(
        original_counts.enters, 1,
        "the original no-receipt path still walks"
    );
    assert_eq!(f.node.state_at(child).unwrap(), actual_child);
    assert_eq!(f.node.read_active().unwrap(), before_active);
    assert_eq!(
        load_observed(&f.node.db, child, None).unwrap(),
        before_record
    );
    assert_eq!(deltas(&f.node.db, child).unwrap(), before_deltas);
    assert_eq!(f.node.db.total_changes(), before_changes);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn same_accounts_root_cannot_hide_changed_non_account_complete_state() {
    let f = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&f.node, &mut counts);
    let mut changed = f.node.settings.initial.clone();
    changed.insert("retained:post-write-full-state".into(), Value::Null);
    let before = complete(&f.node.settings, &f.node.settings.initial).unwrap();
    let after = complete(&f.node.settings, &changed).unwrap();
    assert_eq!(before.account_root, after.account_root);
    assert_ne!(before.non_account_root, after.non_account_root);
    let error = verify(
        &f.node,
        f.node.settings.genesis(),
        &changed,
        &mut readback,
        &mut counts,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_STATE_ROOT");
    assert!(error.requires_owner_stop());
    assert_eq!(readback.hits, 0);
    assert_eq!(counts.enters, 1);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn same_record_on_another_connection_cannot_borrow_the_first_graph() {
    let a = fixture();
    let b = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&a.node, &mut counts);
    verify(
        &a.node,
        a.node.settings.genesis(),
        &a.node.settings.initial,
        &mut readback,
        &mut counts,
    )
    .unwrap();
    assert_eq!(readback.hits, 1);
    assert_eq!(
        load_observed(&a.node.db, a.node.settings.genesis(), None).unwrap(),
        load_observed(&b.node.db, b.node.settings.genesis(), None).unwrap()
    );
    b.node.db.execute("DELETE FROM archive_nodes", []).unwrap();
    let error = verify(
        &b.node,
        b.node.settings.genesis(),
        &b.node.settings.initial,
        &mut readback,
        &mut counts,
    )
    .unwrap_err();
    assert!(error.requires_owner_stop());
    assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE:"));
    assert!(error
        .to_string()
        .ends_with("write snapshot belongs to another connection"));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(readback.hits, 1);
    assert!(verify_state_with_native_progress(
        &b.node.db,
        &b.node.settings,
        b.node.settings.genesis(),
        &b.node.settings.initial,
        &mut Counts::default(),
        None
    )
    .is_err());
    drop(readback);
    a.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn no_row_write_and_reversed_ddl_stickily_restore_original_graph_validation() {
    for sql in [
        "UPDATE archive_nodes SET data=data WHERE 0",
        "UPDATE archive_nodes SET data=data",
        "CREATE TEMP VIEW transient_readback AS SELECT 1; DROP VIEW transient_readback",
    ] {
        let f = fixture();
        let mut counts = Counts::default();
        let mut readback = mint_genesis(&f.node, &mut counts);
        let schema = readback_schema(&f.node.db).unwrap();
        f.node.db.execute_batch(sql).unwrap();
        assert_eq!(readback_schema(&f.node.db).unwrap(), schema);
        for expected_graphs in [2, 3] {
            verify(
                &f.node,
                f.node.settings.genesis(),
                &f.node.settings.initial,
                &mut readback,
                &mut counts,
            )
            .unwrap();
            assert_eq!(counts.enters, expected_graphs);
            assert!(!readback.enabled);
            assert!(readback.graphs.iter().all(Option::is_none));
            assert_eq!(readback.hits, 0);
        }
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn graph_damage_after_a_real_receipt_is_reread_and_rejected() {
    let f = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&f.node, &mut counts);
    f.node.db.execute("DELETE FROM archive_nodes", []).unwrap();
    let error = verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut readback,
        &mut counts,
    )
    .unwrap_err();
    assert!(error.requires_owner_stop());
    assert_eq!(counts.enters, 2);
    assert_eq!(readback.hits, 0);
    assert!(!readback.enabled);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
    verify_state_with_native_progress(
        &f.node.db,
        &f.node.settings,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut Counts::default(),
        None,
    )
    .unwrap();
}

#[test]
fn a_write_during_the_first_graph_never_mints_a_retained_graph_result() {
    for inject_at_exit in [false, true] {
        let f = fixture();
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut readback = start(&f.node, f.node.settings.genesis());
        let mut counts = Counts::default();
        let mut injected = false;
        verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut TypedNativeProgress(|point| {
                if let NativeProgressPoint::AccountGraph(point) = point {
                    let inject = if inject_at_exit {
                        matches!(point.kind(), AccountGraphKind::Exit { .. })
                    } else {
                        matches!(point.kind(), AccountGraphKind::Enter)
                    };
                    if inject && !injected {
                        injected = true;
                        f.node
                            .db
                            .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                    }
                    counts.account_graph(point)?;
                } else {
                    counts.checkpoint()?;
                }
                Ok(())
            }),
        )
        .unwrap();
        assert!(injected);
        assert_eq!(counts.enters, 1);
        assert!(readback.graphs.iter().all(Option::is_none));
        verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut counts,
        )
        .unwrap();
        assert_eq!(counts.enters, 2);
        assert_eq!(readback.hits, 0);
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn final_boundary_write_after_a_match_forces_fresh_original_verification() {
    let f = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&f.node, &mut counts);
    // Typed graph points are counted separately, so the original verifier's
    // boundary count locates the final boundary on its first attempted hit.
    let last = counts.boundaries;
    assert!(last > 0);
    let mut boundaries = 0;
    let mut injected = false;
    let mut fallback_graphs = 0;
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut readback,
        &mut TypedNativeProgress(|point| {
            match point {
                NativeProgressPoint::Boundary => {
                    boundaries += 1;
                    if boundaries == last && !injected {
                        injected = true;
                        f.node
                            .db
                            .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                    }
                }
                NativeProgressPoint::AccountGraph(point)
                    if matches!(point.kind(), AccountGraphKind::Enter) =>
                {
                    fallback_graphs += 1
                }
                _ => {}
            }
            Ok(())
        }),
    )
    .unwrap();
    assert!(injected);
    assert_eq!(fallback_graphs, 1);
    assert_eq!(
        readback.hits, 0,
        "the invalidated match is not counted as a hit"
    );
    assert!(!readback.enabled);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn outer_state_at_final_callback_cannot_mutate_a_consumed_child_snapshot() {
    let mut f = fixture();
    let genesis = f.node.settings.genesis();
    let packet = f
        .node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let child = f.node.admit(&packet, 100_000).unwrap();
    let state = f.node.state_at(child).unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut readback = start(&f.node, child);
    verify(
        &f.node,
        child,
        &state,
        &mut readback,
        &mut Counts::default(),
    )
    .unwrap();
    let mut positive = Counts::default();
    assert_eq!(
        f.node
            .state_at_with_post_write_readback(child, &mut positive, &mut readback,)
            .unwrap(),
        state
    );
    assert_eq!(readback.hits, 1);
    assert_eq!(positive.enters, 0);
    let last = positive.boundaries;
    let mut calls = 0;
    let error = f
        .node
        .state_at_with_post_write_readback(
            child,
            &mut || {
                calls += 1;
                if calls == last {
                    f.node.db.execute(
                        "UPDATE snapshots SET state=X'7B7D' WHERE block=?",
                        [child.as_slice()],
                    )?;
                }
                Ok(())
            },
            &mut readback,
        )
        .unwrap_err();
    assert_eq!(calls, last);
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert!(error.requires_owner_stop());
    assert!(readback.validate_consumed(&f.node.db).is_err());
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.node.state_at(child).unwrap(), state);
}

#[test]
fn commit_begin_and_savepoint_aba_cannot_remint_or_reuse_the_original_owner() {
    for sql in [
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT graph_aba; ROLLBACK TO graph_aba; RELEASE graph_aba",
    ] {
        let f = fixture();
        let mut counts = Counts::default();
        let mut readback = mint_genesis(&f.node, &mut counts);
        let original_owner = TransactionScope::capture(&f.node.db).unwrap();
        let before_changes = f.node.db.total_changes();
        f.node.db.execute_batch(sql).unwrap();
        assert!(!f.node.db.is_autocommit());
        assert_eq!(f.node.db.total_changes(), before_changes);
        assert!(PostWriteReadback::new(
            &f.node.db,
            &f.node.settings,
            f.node.settings.genesis(),
            &original_owner,
            f.node
                .post_write_schema
                .as_ref()
                .expect("ordinary writer source schema")
        )
        .is_err());
        let error = verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut counts,
        )
        .unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE:"));
        assert!(error
            .to_string()
            .ends_with("executed transaction control crossed read scope"));
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(counts.enters, 1);
        assert_eq!(readback.hits, 0);
        drop(readback);
        // This only closes the currently active transaction. It does not undo
        // a callback's already-executed COMMIT or resurrect the original scope.
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn trusted_reset_exposes_preexisting_catalog_and_cached_vm_divergence_before_mint() {
    for capacity in [0, 16] {
        let f = fixture();
        f.node.db.set_prepared_statement_cache_capacity(capacity);
        let genesis = f.node.settings.genesis();
        let mut counts = Counts::default();
        verify_state_with_native_progress(
            &f.node.db,
            &f.node.settings,
            genesis,
            &f.node.settings.initial,
            &mut counts,
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap();
        assert_eq!(counts.enters, 1);
        // This pure SQL mutation deliberately precedes BEGIN/capture. Merely
        // comparing catalog rows before/after a graph would miss the stale
        // parsed schema and prepared SELECTs that still use the old rootpage.
        f.node.db.execute_batch(
            "PRAGMA writable_schema=ON;
             UPDATE main.sqlite_schema SET rootpage=(SELECT rootpage FROM main.sqlite_schema WHERE name='native_state_commitments') WHERE name='archive_nodes';
             PRAGMA writable_schema=OFF",
        ).unwrap();
        assert_eq!(
            &super::super::schema(&f.node.db).unwrap(),
            f.node
                .post_write_schema
                .as_ref()
                .expect("ordinary writer source schema")
        );
        verify_state_with_native_progress(
            &f.node.db,
            &f.node.settings,
            genesis,
            &f.node.settings.initial,
            &mut counts,
            Some(&f.node.authenticated_arithmetic),
        )
        .unwrap();
        assert_eq!(
            counts.enters, 2,
            "the unnormalized actual cached graph still passes"
        );
        f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut readback = start(&f.node, genesis);
        let error = verify(
            &f.node,
            genesis,
            &f.node.settings.initial,
            &mut readback,
            &mut counts,
        )
        .unwrap_err();
        assert!(error.requires_owner_stop());
        assert_eq!(
            counts.enters, 3,
            "the normalized actual graph is what rejects"
        );
        assert!(readback.graphs.iter().all(Option::is_none));
        assert_eq!(readback.hits, 0);
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn prepare_only_reset_after_normalization_cannot_switch_the_unchanged_graph() {
    let f = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&f.node, &mut counts);
    let original_schema = readback_schema(&f.node.db).unwrap();
    let changes = f.node.db.total_changes();
    // SQLite applies this reset during prepare; do not step the statement.
    drop(f.node.db.prepare("PRAGMA writable_schema=RESET").unwrap());
    assert_eq!(f.node.db.total_changes(), changes);
    assert_eq!(readback_schema(&f.node.db).unwrap(), original_schema);
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut readback,
        &mut counts,
    )
    .unwrap();
    assert_eq!(counts.enters, 1);
    assert_eq!(readback.hits, 1);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn configuration_and_namespace_changes_disable_reuse_with_the_original_fallback() {
    for sql in [
        "PRAGMA writable_schema=ON",
        "ATTACH ':memory:' AS extra_readback",
        "CREATE TEMP TABLE unrelated_readback(value INTEGER)",
    ] {
        let f = fixture();
        let mut counts = Counts::default();
        let mut readback = mint_genesis(&f.node, &mut counts);
        f.node.db.execute_batch(sql).unwrap();
        verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut counts,
        )
        .unwrap();
        assert_eq!(counts.enters, 2);
        assert!(!readback.enabled);
        assert_eq!(readback.hits, 0);
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn original_immediate_writer_blocks_an_external_writer_without_freezing_callbacks() {
    let f = fixture();
    let mut counts = Counts::default();
    let mut readback = mint_genesis(&f.node, &mut counts);
    let other = Connection::open(f.node.directory.join("native.sqlite")).unwrap();
    other.busy_timeout(std::time::Duration::ZERO).unwrap();
    let error = other.execute("DELETE FROM archive_nodes", []).unwrap_err();
    assert!(matches!(error, rusqlite::Error::SqliteFailure(code, _)
        if code.code == rusqlite::ErrorCode::DatabaseBusy));
    let calls = Cell::new(0);
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut readback,
        &mut || {
            calls.set(calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert!(calls.get() > 0);
    assert_eq!(readback.hits, 1);
    drop(readback);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn cancellation_before_or_after_a_match_returns_the_original_error_without_a_hit() {
    for at_final in [false, true] {
        let f = fixture();
        let mut counts = Counts::default();
        let mut readback = mint_genesis(&f.node, &mut counts);
        let mut hit_counts = Counts::default();
        verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut hit_counts,
        )
        .unwrap();
        assert_eq!(readback.hits, 1);
        let cancel_at = if at_final { hit_counts.boundaries } else { 1 };
        let mut calls = 0;
        let error = verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut readback,
            &mut || {
                calls += 1;
                if calls == cancel_at {
                    Err("FRAME_DEADLINE".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(calls, cancel_at);
        assert!(error.is(ErrorCode::FrameDeadline));
        assert!(!error.requires_owner_stop());
        assert_eq!(readback.hits, 1);
        drop(readback);
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}
