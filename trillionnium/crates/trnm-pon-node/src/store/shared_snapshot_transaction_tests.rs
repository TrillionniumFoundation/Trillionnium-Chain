//! Additional transaction-fence controls; not native caller qualification.
use super::*;

#[test]
fn borrowed_and_owned_read_scopes_refuse_readonly_commit_begin_aba() {
    for borrowed in [false, true] {
        let f = fixture();
        if borrowed {
            f.node.db.execute_batch("BEGIN; SELECT 1").unwrap();
        }
        let error = in_read_snapshot(&f.node.db, || {
            f.node.db.execute_batch("COMMIT; BEGIN; SELECT 1")?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.requires_owner_stop());
        if borrowed {
            f.node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn final_read_refuses_prepared_end_begin_with_unchanged_counters() {
    let f = fixture();
    let mut end = f
        .node
        .db
        .prepare_cached("\u{feff}/* prepared before scope */ END")
        .unwrap();
    f.node.db.execute_batch("BEGIN; SELECT 1").unwrap();
    let before = (f.node.db.total_changes(), f.node.db.is_autocommit());
    let error = final_read(&f.node.db, || {
        end.execute([])?;
        f.node.db.execute_batch("BEGIN; SELECT 1")?;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(
        (f.node.db.total_changes(), f.node.db.is_autocommit()),
        before
    );
    assert!(error.requires_owner_stop());
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn present_and_absent_loads_refuse_callback_transaction_replacement() {
    for present in [true, false] {
        let f = fixture();
        let block = if present { f.block } else { [255; 32] };
        f.node.db.execute_batch("BEGIN; SELECT 1").unwrap();
        let mut replaced = false;
        let error = load(
            &f.node.db,
            &f.node.settings,
            block,
            &mut || {
                if !replaced {
                    f.node.db.execute_batch("/*callback*/ COMMIT; BEGIN")?;
                    replaced = true;
                }
                Ok(())
            },
            &f.node.authenticated_arithmetic,
        )
        .unwrap_err();
        assert!(replaced);
        assert!(error.requires_owner_stop());
        f.node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn detection_does_not_claim_to_undo_a_prior_commit() {
    let f = fixture();
    f.node
        .db
        .execute_batch(
            "CREATE TABLE committed_control(value); BEGIN; INSERT INTO committed_control VALUES(9)",
        )
        .unwrap();
    let error = in_read_snapshot(&f.node.db, || {
        f.node.db.execute_batch("COMMIT; BEGIN")?;
        Ok(())
    })
    .unwrap_err();
    assert!(error.requires_owner_stop());
    f.node.db.execute_batch("ROLLBACK").unwrap();
    let value: i64 = f
        .node
        .db
        .query_row("SELECT value FROM committed_control", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, 9);
}

#[test]
fn callback_first_error_does_not_mask_transaction_replacement() {
    let f = fixture();
    f.node.db.execute_batch("BEGIN").unwrap();
    let error = load(
        &f.node.db,
        &f.node.settings,
        f.block,
        &mut || {
            f.node.db.execute_batch("COMMIT; BEGIN")?;
            Err(Error::from("TRANSACTION_CONTROL_FIRST_ERROR"))
        },
        &f.node.authenticated_arithmetic,
    )
    .unwrap_err();
    assert!(error.requires_owner_stop());
    assert!(format!("{error:?}").contains("TRANSACTION_CONTROL_FIRST_ERROR"));
    f.node.db.execute_batch("ROLLBACK").unwrap();
}
