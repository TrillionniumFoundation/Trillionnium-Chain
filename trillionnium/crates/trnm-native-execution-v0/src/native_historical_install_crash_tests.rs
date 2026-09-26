// Included only in the genuine later-checkpoint test namespace. These cuts
// exercise schema12 installation, not post-base execution or C33 readiness.

#[cfg(unix)]
#[test]
#[ignore = "dedicated historical installation SIGKILL subprocess entry"]
fn historical_replay_install_sigkill_child() {
    let path = std::path::PathBuf::from(
        std::env::var_os("TRNM_HISTORICAL_INSTALL_CRASH_STORE").expect("child store"),
    );
    let history = crate::NativeHistoricalReplayV1::decode_v1(
        &std::fs::read(path.with_extension("nhr1")).unwrap(),
    )
    .unwrap();
    let header = decode_block_header_v0_exact(&history.anchor_header_cev0).unwrap();
    let application =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let head = application.confirmed_committed_head_v0().unwrap();
    let sequence = historical_fixture_state(&path).sequence;
    let anchor = application
        .confirm_historical_replay_anchor_v1(&head, sequence, &header)
        .unwrap();
    let prepared = application
        .prepare_historical_replay_base_v1(
            &anchor,
            &history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let _confirmed = application
        .install_historical_replay_base_v1(&prepared)
        .unwrap();
    panic!("historical installation SIGKILL stage was not reached");
}

#[cfg(unix)]
struct HistoricalInstallCrashExpectationV1 {
    target_head: trnm_native_application::ApplicationHeadV0,
    input_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    source_sequence: u64,
    retained_rows: Vec<(String, Vec<Vec<rusqlite::types::Value>>)>,
}

#[cfg(unix)]
fn assert_historical_install_crash_state_v1(
    path: &std::path::Path,
    fixture: &NonemptyHistoricalReplayFixture,
    expected: &HistoricalInstallCrashExpectationV1,
) {
    assert_eq!(historical_retained_rows(path), expected.retained_rows);
    let state = historical_fixture_state(path);
    assert_eq!(state.sequence, expected.source_sequence + 1);
    assert_eq!(state.commands, fixture.target_state.commands);
    assert_eq!(state.nonces, fixture.target_state.nonces);
    assert_eq!(state.commands.len(), 3, "real nonempty command replay set");
    assert_eq!(
        state.nonces.len(),
        3,
        "real nonempty signer/nonce replay set"
    );
    let snapshot_digest: [u8; 32] = sha2::Sha256::digest(&state.snapshot).into();
    assert_eq!(snapshot_digest, expected.snapshot_digest);
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let phase: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = sql
        .query_row(
            "SELECT phase,consumed_block,consumed_sequence FROM native_later_epoch_edge_v1
             WHERE checkpoint_block=?1",
            [fixture.source_header.id().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(phase, (0, None, None), "source B must remain Installed");
    let counts: (i64, i64, i64) = sql
        .query_row(
            "SELECT (SELECT COUNT(*) FROM native_historical_replay_base_v1),
                    (SELECT COUNT(*) FROM native_replay_execution_p_v1),
                    (SELECT COUNT(*) FROM native_replay_execution_finality_v1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        counts,
        (1, 0, 0),
        "installation never invents a post-base P"
    );
}

#[cfg(unix)]
#[test]
#[inline(never)]
fn historical_replay_install_sigkill_cuts_recover_exact_nonempty_base() {
    use std::os::unix::process::ExitStatusExt;

    let seed_directory = tempfile::tempdir().unwrap();
    let sender_path = seed_directory.path().join("history-sender.sqlite3");
    let receiver_path = seed_directory.path().join("history-receiver-c18.sqlite3");
    let fixture = build_nonempty_historical_replay_fixture(&sender_path, &receiver_path);
    let encoded_history = fixture.history.encode_v1().unwrap();
    let expected = {
        let application =
            DurableNativeApplicationV0::open(&receiver_path, native_checkpoint_fixture_config_v1())
                .unwrap();
        let anchor = application
            .confirm_historical_replay_anchor_v1(
                &fixture.source_head,
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
        assert_eq!(prepared.target_head().height().get(), 32);
        assert_eq!(prepared.application_count(), 10);
        let expected = HistoricalInstallCrashExpectationV1 {
            target_head: prepared.target_head().clone(),
            input_digest: prepared.input_digest(),
            snapshot_digest: prepared.snapshot_digest(),
            source_sequence: prepared.source_sequence(),
            retained_rows: historical_retained_rows(&receiver_path),
        };
        assert_eq!(expected.retained_rows.len(), 9);
        drop(prepared);
        drop(anchor);
        drop(application);
        expected
    };

    for stage in [
        "historical_install_before_commit",
        "historical_install_before_fsync",
        "historical_install_after_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        copy_later_store(&receiver_path, &path);
        std::fs::write(path.with_extension("nhr1"), &encoded_history).unwrap();
        let marker = directory.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "later_epoch_checkpoint_bridge::tests::historical_replay_install_sigkill_child",
                "--nocapture",
            ])
            .env_remove("RUST_MIN_STACK")
            .env_remove("RUST_LOG")
            .env("TRNM_HISTORICAL_INSTALL_CRASH_STORE", &path)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while std::fs::read_to_string(&marker).ok().as_deref() != Some(stage)
            && std::time::Instant::now() < deadline
        {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if std::fs::read_to_string(&marker).ok().as_deref() != Some(stage) {
            let _ = child.kill();
            let status = child.wait().unwrap();
            panic!("historical child did not reach {stage} within 120 seconds: {status}");
        }
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), stage);
        child.kill().unwrap();
        assert_eq!(
            child.wait().unwrap().signal(),
            Some(9),
            "real SIGKILL required"
        );

        let (application, confirmed) = if stage == "historical_install_before_commit" {
            // Explicit cold open performs the actual rollback recovery but
            // refuses the resulting schema10 instead of migrating it.
            let error = DurableNativeApplicationV0::open_historical_replay_v1(
                &path,
                native_checkpoint_fixture_config_v1(),
            )
            .unwrap_err();
            assert_eq!(error.field(), "historical.open_exact_schema12");
            assert_eq!(historical_fixture_state(&path), fixture.source_state);
            assert_eq!(historical_retained_rows(&path), expected.retained_rows);
            let application =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            assert_eq!(
                application.confirmed_committed_head_v0().unwrap(),
                fixture.source_head
            );
            let anchor = application
                .confirm_historical_replay_anchor_v1(
                    &fixture.source_head,
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
            assert_eq!(prepared.target_head(), &expected.target_head);
            assert_eq!(prepared.input_digest(), expected.input_digest);
            let confirmed = application
                .install_historical_replay_base_v1(&prepared)
                .unwrap();
            (application, confirmed)
        } else {
            let application = DurableNativeApplicationV0::open_historical_replay_v1(
                &path,
                native_checkpoint_fixture_config_v1(),
            )
            .unwrap();
            let confirmed = application
                .confirm_historical_replay_base_v1(expected.input_digest, &expected.target_head)
                .unwrap();
            (application, confirmed)
        };
        assert!(confirmed.belongs_to_application(&application));
        assert_eq!(confirmed.source_head(), &fixture.source_head);
        assert_eq!(confirmed.target_head(), &expected.target_head);
        assert_eq!(confirmed.input_digest(), expected.input_digest);
        assert_eq!(confirmed.install_sequence(), expected.source_sequence + 1);
        let base_digest = confirmed.base_digest();
        assert_historical_install_crash_state_v1(&path, &fixture, &expected);
        drop(application);

        let ordinary_error =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                .unwrap_err();
        assert_eq!(
            ordinary_error.field(),
            "schema.exact",
            "must refuse12, not merely be Busy"
        );
        let cold = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        assert!(!confirmed.belongs_to_application(&cold));
        let repeated = cold
            .confirm_historical_replay_base_v1(expected.input_digest, &expected.target_head)
            .unwrap();
        assert!(repeated.belongs_to_application(&cold));
        assert_eq!(repeated.base_digest(), base_digest);
        assert_eq!(repeated.install_sequence(), expected.source_sequence + 1);
        assert_eq!(repeated.target_head(), &expected.target_head);
        assert_historical_install_crash_state_v1(&path, &fixture, &expected);
    }
}
