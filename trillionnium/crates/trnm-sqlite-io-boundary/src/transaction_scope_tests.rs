//! New control source only until separately compiled/executed and receipted.
use super::*;

#[test]
fn token_controls_cover_sqlite_space_comments_bom_aliases_and_identifier_boundaries() {
    for sql in [
        "BEGIN",
        "COMMIT",
        "END TRANSACTION",
        "ROLLBACK TO SAVEPOINT x",
        "SAVEPOINT x",
        "RELEASE SAVEPOINT x",
        "\u{feff}/*lead*/ --line\n; eNd;",
        " \u{000b}\u{000c}\t\r\n/*a*//*b*/savepoint x",
        "/* nonnested /* */COMMIT",
        ";; --x\nROLLBACK",
    ] {
        assert!(transaction_control(sql.as_bytes()), "{sql:?}");
    }
    for sql in [
        "",
        "-- COMMIT",
        "/* COMMIT",
        "/* COMMIT */ SELECT 1",
        "SELECT 'COMMIT'",
        "BEGINNING",
        "BEGIN_",
        "BEGIN$",
        "BEGINé",
        "\u{000b}BEGIN",
        "\"COMMIT\"",
        "[END]",
        "EXPLAIN COMMIT",
        "EXPLAIN QUERY PLAN SELECT 1",
        "/*x*/;",
    ] {
        assert!(!transaction_control(sql.as_bytes()), "{sql:?}");
    }
}

#[test]
fn actual_readonly_aba_is_not_an_autocommit_changes_or_schema_identity() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("BEGIN; SELECT 1").unwrap();
    let before = (
        db.is_autocommit(),
        db.total_changes(),
        db.query_row::<i64, _, _>("PRAGMA schema_version", [], |r| r.get(0))
            .unwrap(),
    );
    let scope = TransactionScope::capture(&db).unwrap();
    db.execute_batch("/*readonly*/ COMMIT; -- ABA\n BEGIN; SELECT 1")
        .unwrap();
    let after = (
        db.is_autocommit(),
        db.total_changes(),
        db.query_row::<i64, _, _>("PRAGMA schema_version", [], |r| r.get(0))
            .unwrap(),
    );
    assert_eq!(before, after);
    assert!(scope.unchanged().is_err());
    db.execute_batch("ROLLBACK").unwrap();

    db.execute_batch("BEGIN").unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    assert!(db
        .execute_batch("COMMIT; BEGIN; SELECT missing_scope_column")
        .is_err());
    assert!(scope.unchanged().is_err());
    db.execute_batch("ROLLBACK").unwrap();

    db.execute_batch("BEGIN").unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    assert!(db.execute_batch("BEGIN").is_err());
    assert!(scope.unchanged().is_err());
    db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn already_prepared_cached_end_is_observed_at_execution_and_reuse() {
    let db = Connection::open_in_memory().unwrap();
    // Prepare before the observer exists. No prepare-time authorizer can be
    // credited with detecting these subsequent executions/re-executions.
    let mut end = db.prepare_cached("\u{feff}/*x*/ END TRANSACTION").unwrap();
    for _ in 0..2 {
        db.execute_batch("BEGIN; SELECT 1").unwrap();
        let scope = TransactionScope::capture(&db).unwrap();
        end.execute([]).unwrap();
        db.execute_batch("BEGIN; SELECT 1").unwrap();
        assert!(scope.unchanged().is_err());
        db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn savepoint_release_and_rollback_to_are_conservatively_refused() {
    for command in [
        "SAVEPOINT scope_inner",
        "RELEASE scope_inner",
        "ROLLBACK TO scope_inner",
    ] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("BEGIN; SAVEPOINT scope_inner").unwrap();
        let scope = TransactionScope::capture(&db).unwrap();
        db.execute_batch(command).unwrap();
        assert!(scope.unchanged().is_err(), "{command}");
        db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn nested_scopes_share_epoch_and_other_connections_do_not_invalidate_reads() {
    let db = Connection::open_in_memory().unwrap();
    let other = Connection::open_in_memory().unwrap();
    db.execute_batch("BEGIN; SELECT 1").unwrap();
    let outer = TransactionScope::capture(&db).unwrap();
    let inner = TransactionScope::capture(&db).unwrap();
    assert_eq!(outer.observer, inner.observer);
    other
        .execute_batch("BEGIN; CREATE TABLE separate(x); INSERT INTO separate VALUES(1); COMMIT")
        .unwrap();
    let _: i64 = db.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
    inner.unchanged().unwrap();
    outer.unchanged().unwrap();
    db.execute_batch("COMMIT; BEGIN").unwrap();
    assert!(inner.unchanged().is_err());
    assert!(outer.unchanged().is_err());
    db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn explain_does_not_execute_a_transaction_control() {
    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    let mut explain = db.prepare("EXPLAIN COMMIT").unwrap();
    let mut rows = explain.query([]).unwrap();
    while rows.next().unwrap().is_some() {}
    scope.unchanged().unwrap();
    // Syntax rejection occurs before execution, not an epoch transition. In
    // contrast, an executed failed BEGIN above is conservatively refused.
    assert!(db
        .execute_batch("/* malformed */ COMMIT unexpected words")
        .is_err());
    scope.unchanged().unwrap();
}

#[test]
fn replacing_trace_is_detected_by_actual_execution_probe_without_resetting_epoch() {
    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    // Deliberate unsafe out-of-domain perturbation, not a supported caller API.
    unsafe { ffi::sqlite3_trace_v2(db.handle(), 0, None, ptr::null_mut()) };
    assert!(scope.unchanged().is_err());
    assert!(TransactionScope::capture(&db).is_err());
}

#[test]
fn overflow_wrong_pid_and_wrong_handle_are_sticky_refusals() {
    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    let state = unsafe { &*scope.observer };
    state.statements.store(u64::MAX, Ordering::SeqCst);
    assert!(scope.unchanged().is_err());
    assert!(TransactionScope::capture(&db).is_err());

    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    unsafe { (*scope.observer).pid = std::process::id().wrapping_add(1) };
    assert!(scope.unchanged().is_err());

    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    // Perturb only the callback statement, not the owner's handle used at close.
    unsafe {
        trace(
            ffi::SQLITE_TRACE_STMT as c_uint,
            scope.observer.cast(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert!(scope.unchanged().is_err());

    let db = Connection::open_in_memory().unwrap();
    let other = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    let _prepared_on_other = other.prepare("SELECT 1").unwrap();
    let foreign_statement = unsafe { ffi::sqlite3_next_stmt(other.handle(), ptr::null_mut()) };
    assert!(!foreign_statement.is_null());
    unsafe {
        trace(
            ffi::SQLITE_TRACE_STMT as c_uint,
            scope.observer.cast(),
            foreign_statement.cast(),
            ptr::null_mut(),
        )
    };
    assert!(scope.unchanged().is_err());
}

#[test]
fn dropping_scopes_does_not_drop_or_reinstall_the_connection_observer() {
    let db = Connection::open_in_memory().unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    let pointer = scope.observer;
    drop(scope);
    db.execute_batch("BEGIN; COMMIT").unwrap();
    let scope = TransactionScope::capture(&db).unwrap();
    assert_eq!(scope.observer, pointer);
    assert!(unsafe { &*pointer }.controls.load(Ordering::SeqCst) >= 2);
    drop(scope);
    db.close().unwrap();
}
