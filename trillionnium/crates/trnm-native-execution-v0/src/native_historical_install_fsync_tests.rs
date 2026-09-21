// Included by native_historical_replay_tests after the genuine C18 fixture
// helpers.  These tests inject the host durability fence, not SQLite writes.

#[test]
fn historical_replay_install_and_confirm_fsync_uncertainty_is_idempotent() {
    use crate::{NativeApplicationExecutionErrorCodeV0, NativeApplicationExecutionErrorV0};
    let seed_directory = tempfile::tempdir().unwrap();
    let sender_path = seed_directory.path().join("history-sender.sqlite3");
    let receiver_path = seed_directory.path().join("history-receiver-c18.sqlite3");
    let fixture = build_nonempty_historical_replay_fixture(&sender_path, &receiver_path);
    let history_rows = historical_retained_rows(&receiver_path);
    let source_p_count = history_rows
        .iter()
        .find(|(name, _)| name == "native_durable_execution_p_v1")
        .unwrap()
        .1
        .len() as i64;
    let points = [
        (
            crate::durable::SyncStoreCommitBoundaryFaultPointV0::Database,
            "historical.install_fsync",
            "historical.confirm_fsync",
        ),
        (
            crate::durable::SyncStoreCommitBoundaryFaultPointV0::Directory,
            "historical.install_directory_fsync",
            "historical.confirm_directory_fsync",
        ),
    ];

    for (point, install_field, confirm_field) in points {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        copy_later_store(&receiver_path, &path);

        let application =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let source_head = application.confirmed_committed_head_v0().unwrap();
        let anchor = application
            .confirm_historical_replay_anchor_v1(
                &source_head,
                fixture.source_state.sequence,
                &fixture.source_header,
            )
            .unwrap();
        let prepared = application
            .prepare_historical_replay_base_v1(
                &anchor,
                &fixture.history,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let input_digest = prepared.input_digest();
        let target_head = prepared.target_head().clone();
        let assert_uncertain_install_persisted = || {
            let sql = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let installed: bool = sql.query_row(
                "SELECT schema_version=?1 AND durable_sequence=?2 AND (SELECT COUNT(*) FROM native_historical_replay_base_v1)=1 FROM native_application_metadata_v0 WHERE singleton=1",
                rusqlite::params![12_u64.to_be_bytes().as_slice(), (fixture.source_state.sequence + 1).to_be_bytes().as_slice()],
                |row| row.get(0),
            ).unwrap();
            assert!(installed, "the injected fsync error occurs after COMMIT");
            assert_eq!(historical_retained_rows(&path), history_rows);
        };

        let fault =
            crate::durable::arm_sync_store_commit_boundary_fault_v0(application.path(), point);
        let error = application
            .install_historical_replay_base_v1(&prepared)
            .err()
            .expect("install must report an uncertain durability fence");
        let error = error
            .downcast_ref::<NativeApplicationExecutionErrorV0>()
            .expect("uncertain install error type");
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::CommitUncertain
        );
        assert_eq!(error.field(), install_field);
        drop(fault);
        assert_uncertain_install_persisted();

        let fault =
            crate::durable::arm_sync_store_commit_boundary_fault_v0(application.path(), point);
        let error = application
            .install_historical_replay_base_v1(&prepared)
            .err()
            .expect("same-owner retry must re-establish the fence");
        let error = error
            .downcast_ref::<NativeApplicationExecutionErrorV0>()
            .expect("uncertain retry error type");
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::CommitUncertain
        );
        assert_eq!(error.field(), install_field);
        drop(fault);
        assert_uncertain_install_persisted();

        let confirmed = application
            .install_historical_replay_base_v1(&prepared)
            .expect("clean install retry");
        assert_eq!(confirmed.target_head(), &target_head);
        assert_eq!(confirmed.input_digest(), input_digest);
        let base_digest = confirmed.base_digest();
        drop(prepared);
        drop(anchor);
        drop(application);

        let application = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let fault =
            crate::durable::arm_sync_store_commit_boundary_fault_v0(application.path(), point);
        let error = application
            .confirm_historical_replay_base_v1(input_digest, &target_head)
            .err()
            .expect("confirm must report an uncertain durability fence");
        let error = error
            .downcast_ref::<NativeApplicationExecutionErrorV0>()
            .expect("uncertain confirm error type");
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::CommitUncertain
        );
        assert_eq!(error.field(), confirm_field);
        drop(fault);

        let fault =
            crate::durable::arm_sync_store_commit_boundary_fault_v0(application.path(), point);
        let error = application
            .confirm_historical_replay_base_v1(input_digest, &target_head)
            .err()
            .expect("same-owner confirm retry must re-establish the fence");
        let error = error
            .downcast_ref::<NativeApplicationExecutionErrorV0>()
            .expect("uncertain confirm retry error type");
        assert_eq!(
            error.code(),
            NativeApplicationExecutionErrorCodeV0::CommitUncertain
        );
        assert_eq!(error.field(), confirm_field);
        drop(fault);

        let confirmed = application
            .confirm_historical_replay_base_v1(input_digest, &target_head)
            .expect("clean confirm retry");
        assert_eq!(confirmed.input_digest(), input_digest);
        assert_eq!(confirmed.target_head(), &target_head);
        assert_eq!(confirmed.base_digest(), base_digest);
        assert_eq!(historical_retained_rows(&path), history_rows);
        let state = historical_fixture_state(&path);
        assert_eq!(state.sequence, fixture.source_state.sequence + 1);
        let sql = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let counts: (i64, i64, i64) = sql
            .query_row(
                "SELECT (SELECT COUNT(*) FROM native_replay_execution_p_v1),\n                         (SELECT COUNT(*) FROM native_replay_execution_finality_v1),\n                         (SELECT COUNT(*) FROM native_durable_execution_p_v1)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts.0, 0, "install must not create replay P");
        assert_eq!(counts.1, 0, "install must not create replay finality");
        assert_eq!(
            counts.2, source_p_count,
            "install must retain exactly the source P inventory"
        );
    }
}
