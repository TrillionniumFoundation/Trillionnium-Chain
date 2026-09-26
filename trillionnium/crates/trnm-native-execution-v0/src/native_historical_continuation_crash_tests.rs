// Included in the genuine later-checkpoint test namespace. Every subprocess
// starts from a real installed or prepared receiver and uses ordinary owner APIs.

#[cfg(unix)]
#[test]
#[ignore = "dedicated historical continuation SIGKILL subprocess entry"]
fn historical_replay_continuation_sigkill_child() {
    let path = std::path::PathBuf::from(
        std::env::var_os("TRNM_HISTORICAL_CONTINUATION_CRASH_STORE").expect("child store"),
    );
    let stage = std::env::var("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE").unwrap();
    let artifact = trnm_native_application::decode_native_executed_block_artifact_v0(
        &std::fs::read(path.with_extension("c33-artifact")).unwrap(),
    )
    .unwrap();
    let header =
        decode_block_header_v0_exact(&std::fs::read(path.with_extension("c33-header")).unwrap())
            .unwrap();
    let proof = std::fs::read(path.with_extension("c33-proof")).unwrap();
    let p_digest: [u8; 32] = std::fs::read(path.with_extension("c33-p-digest"))
        .unwrap()
        .try_into()
        .unwrap();
    let owner = DurableNativeApplicationV0::open_historical_replay_v1(
        &path,
        native_checkpoint_fixture_config_v1(),
    )
    .unwrap();
    let head = owner.confirmed_replay_head_v1().unwrap();
    assert_eq!(head.height().get(), 32);
    // Artifact bytes are inert input. The child independently obtains its own
    // exact local parent rather than accepting the sender's application commit.
    let request = historical_continuation_request(artifact.request(), &head);
    assert_eq!(request.parent(), &head);
    assert_eq!(request.block_id().as_bytes(), header.id().as_bytes());
    if stage.starts_with("replay_prepare_") {
        let _prepared = owner
            .prepare_replay_execution_v1(&request, &header)
            .unwrap();
    } else {
        assert!(stage.starts_with("replay_commit_"));
        let prepared = owner
            .reopen_prepared_replay_execution_v1(*header.id().as_bytes(), p_digest)
            .unwrap();
        let _committed = owner
            .commit_replay_finality_bytes_v1(
                &prepared,
                &proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
    }
    panic!("historical continuation SIGKILL stage was not reached: {stage}");
}

#[cfg(unix)]
fn kill_historical_continuation_child_v1(path: &std::path::Path, stage: &str) {
    use std::os::unix::process::ExitStatusExt;

    let marker = path.with_extension("kill-ready");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "later_epoch_checkpoint_bridge::tests::historical_replay_continuation_sigkill_child",
            "--nocapture",
        ])
        .env_remove("RUST_MIN_STACK")
        .env_remove("RUST_LOG")
        .env("TRNM_HISTORICAL_CONTINUATION_CRASH_STORE", path)
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
        panic!("continuation child did not reach {stage} within 120 seconds: {status}");
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), stage);
    child.kill().unwrap();
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(9),
        "real SIGKILL required"
    );
}

#[cfg(unix)]
struct HistoricalContinuationCrashExpectationV1 {
    base_head: trnm_native_application::ApplicationHeadV0,
    target_head: trnm_native_application::ApplicationHeadV0,
    base_state: HistoricalFixtureState,
    target_state: HistoricalFixtureState,
    block_id: [u8; 32],
    p_digest: [u8; 32],
    p_sequence: u64,
    original_proof: Vec<u8>,
    retained_rows: Vec<(String, Vec<Vec<rusqlite::types::Value>>)>,
    source_journal: Vec<u8>,
    source_checkpoint: [u8; 32],
}

#[cfg(unix)]
fn assert_historical_continuation_crash_state_v1(
    path: &std::path::Path,
    expected: &HistoricalContinuationCrashExpectationV1,
    has_p: bool,
    committed: bool,
) {
    assert!(!committed || has_p);
    assert_eq!(historical_retained_rows(path), expected.retained_rows);
    let journal = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(path);
    assert_eq!(std::fs::read(journal).unwrap(), expected.source_journal);
    let sequence = expected.base_state.sequence + u64::from(has_p) + u64::from(committed);
    assert_eq!(
        historical_continuation_counts(path),
        (sequence, i64::from(has_p), i64::from(committed))
    );
    let state = historical_fixture_state(path);
    assert_eq!(state.sequence, sequence);
    let expected_state = if committed {
        &expected.target_state
    } else {
        &expected.base_state
    };
    assert_eq!(state.snapshot, expected_state.snapshot);
    assert_eq!(state.commands, expected_state.commands);
    assert_eq!(state.nonces, expected_state.nonces);
    assert_eq!(state.commands.len(), if committed { 4 } else { 3 });
    assert_eq!(state.nonces.len(), if committed { 4 } else { 3 });
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let phase: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = sql
        .query_row(
            "SELECT phase,consumed_block,consumed_sequence FROM native_later_epoch_edge_v1
             WHERE checkpoint_block=?1",
            [expected.source_checkpoint.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(phase, (0, None, None), "source B must remain Installed");
    if has_p {
        let (digest, p_sequence, status, commit_sequence): (
            Vec<u8>,
            Vec<u8>,
            i64,
            Option<Vec<u8>>,
        ) = sql
            .query_row(
                "SELECT p_digest,p_sequence,status,commit_sequence
                 FROM native_replay_execution_p_v1 WHERE block_id=?1",
                [expected.block_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(digest, expected.p_digest);
        assert_eq!(p_sequence, expected.p_sequence.to_be_bytes());
        assert_eq!(status, i64::from(committed));
        assert_eq!(
            commit_sequence,
            committed.then(|| expected.target_state.sequence.to_be_bytes().to_vec())
        );
    }
    drop(sql);
    if committed {
        assert_historical_continuation_original_proof(
            path,
            expected.block_id,
            expected.p_digest,
            expected.target_state.sequence,
            &expected.original_proof,
        );
    }
}

#[cfg(unix)]
#[test]
#[inline(never)]
fn historical_replay_continuation_sigkill_six_cuts_preserve_exact_c33() {
    let directory = tempfile::tempdir().unwrap();
    let sender_path = directory.path().join("crash-c33-sender.sqlite3");
    let installed_path = directory.path().join("crash-c32-installed.sqlite3");
    let prepared_path = directory.path().join("crash-c33-prepared.sqlite3");
    let fresh = vec![signed_historical_runtime_transaction(
        "native-history-c33-4",
        4,
        trnm_protocol::CanonicalCommandV1::Transfer {
            to: "did:history:recipient".into(),
            amount: 23,
        },
    )];
    let mut fixture = build_nonempty_historical_replay_fixture_with_continuation(
        &sender_path,
        &installed_path,
        &fresh,
    );
    let c33 = commit_genuine_c33_continuation(&sender_path, fixture.continuation.take().unwrap());
    assert_eq!(c33.sender_request.transactions(), fresh);
    let sender_state = historical_fixture_state(&sender_path);
    let retained_rows = historical_retained_rows(&installed_path);
    assert_eq!(retained_rows.len(), 9);
    let source_journal = std::fs::read(
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&installed_path),
    )
    .unwrap();
    let base_head = {
        let owner = DurableNativeApplicationV0::open(
            &installed_path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let anchor = owner
            .confirm_historical_replay_anchor_v1(
                &fixture.source_head,
                fixture.source_state.sequence,
                &fixture.source_header,
            )
            .unwrap();
        let prepared = owner
            .prepare_historical_replay_base_v1(
                &anchor,
                &fixture.history,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let installed = owner.install_historical_replay_base_v1(&prepared).unwrap();
        assert_eq!(
            installed.install_sequence(),
            fixture.source_state.sequence + 1
        );
        installed.target_head().clone()
    };
    let base_state = historical_fixture_state(&installed_path);
    assert_eq!(base_state.commands, fixture.target_state.commands);
    assert_eq!(base_state.nonces, fixture.target_state.nonces);
    let request = historical_continuation_request(&c33.sender_request, &base_head);
    assert_ne!(
        request.parent().commit_id(),
        c33.sender_request.parent().commit_id()
    );
    copy_later_store(&installed_path, &prepared_path);
    let (p_digest, p_sequence, target_head) = {
        let owner = DurableNativeApplicationV0::open_historical_replay_v1(
            &prepared_path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let prepared = owner
            .prepare_replay_execution_v1(&request, &c33.header)
            .unwrap();
        assert_eq!(prepared.p_sequence(), base_state.sequence + 1);
        (
            prepared.p_digest(),
            prepared.p_sequence(),
            prepared.target_head().clone(),
        )
    };
    let (artifact, snapshot, commands, nonces): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = {
        let sql = rusqlite::Connection::open_with_flags(
            &prepared_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        sql.query_row(
            "SELECT artifact,snapshot,commands,nonces FROM native_replay_execution_p_v1 WHERE block_id=?1",
            [c33.header.id().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
    };
    let target_state = HistoricalFixtureState {
        sequence: base_state.sequence + 2,
        snapshot,
        commands: borsh::from_slice(&commands).unwrap(),
        nonces: borsh::from_slice(&nonces).unwrap(),
    };
    assert_eq!(target_state.commands, sender_state.commands);
    assert_eq!(target_state.nonces, sender_state.nonces);
    assert_eq!(target_head.block_id(), c33.sender_head.block_id());
    assert_eq!(target_head.state_root(), c33.sender_head.state_root());
    let expected = HistoricalContinuationCrashExpectationV1 {
        base_head,
        target_head,
        base_state,
        target_state,
        block_id: *c33.header.id().as_bytes(),
        p_digest,
        p_sequence,
        original_proof: c33.original_finality_cev0.clone(),
        retained_rows,
        source_journal,
        source_checkpoint: *fixture.source_header.id().as_bytes(),
    };
    assert_historical_continuation_crash_state_v1(&installed_path, &expected, false, false);
    assert_historical_continuation_crash_state_v1(&prepared_path, &expected, true, false);

    for stage in [
        "replay_prepare_before_commit",
        "replay_prepare_before_fsync",
        "replay_prepare_after_fsync",
        "replay_commit_before_commit",
        "replay_commit_before_fsync",
        "replay_commit_after_fsync",
    ] {
        let cut_directory = tempfile::tempdir().unwrap();
        let path = cut_directory.path().join("application.sqlite3");
        let preparing = stage.starts_with("replay_prepare_");
        copy_later_store(
            if preparing {
                &installed_path
            } else {
                &prepared_path
            },
            &path,
        );
        std::fs::write(path.with_extension("c33-artifact"), &artifact).unwrap();
        std::fs::write(
            path.with_extension("c33-header"),
            c33.header.try_cev0_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(path.with_extension("c33-proof"), &expected.original_proof).unwrap();
        std::fs::write(path.with_extension("c33-p-digest"), expected.p_digest).unwrap();
        kill_historical_continuation_child_v1(&path, stage);

        // Explicit cold open performs actual SQLite rollback when the child
        // died before COMMIT, and independently replays the recovered image.
        let owner = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let had_p = stage != "replay_prepare_before_commit";
        let had_commit = !preparing && stage != "replay_commit_before_commit";
        assert_historical_continuation_crash_state_v1(&path, &expected, had_p, had_commit);
        assert_eq!(
            owner.confirmed_replay_head_v1().unwrap(),
            if had_commit {
                expected.target_head.clone()
            } else {
                expected.base_head.clone()
            }
        );
        let prepared = if preparing {
            owner
                .prepare_replay_execution_v1(&request, &c33.header)
                .unwrap()
        } else {
            owner
                .reopen_prepared_replay_execution_v1(expected.block_id, expected.p_digest)
                .unwrap()
        };
        assert!(prepared.belongs_to_application(&owner));
        assert_eq!(prepared.p_digest(), expected.p_digest);
        assert_eq!(prepared.p_sequence(), expected.p_sequence);
        assert_eq!(prepared.target_head(), &expected.target_head);
        assert_historical_continuation_crash_state_v1(&path, &expected, true, had_commit);
        let committed = owner
            .commit_replay_finality_bytes_v1(
                &prepared,
                &expected.original_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert!(committed.belongs_to_application(&owner));
        assert_eq!(committed.head(), &expected.target_head);
        assert_eq!(committed.p_digest(), expected.p_digest);
        assert_eq!(committed.commit_sequence(), expected.target_state.sequence);
        assert_historical_continuation_crash_state_v1(&path, &expected, true, true);
        drop(owner);

        let error = DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
            .unwrap_err();
        assert_eq!(error.field(), "schema.exact");
        let cold = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        assert!(!prepared.belongs_to_application(&cold));
        assert!(!committed.belongs_to_application(&cold));
        // Exact prepare and commit retries at a progressed cold owner must
        // preserve the original P and commit allocations and proof bytes.
        let retried = cold
            .prepare_replay_execution_v1(&request, &c33.header)
            .unwrap();
        assert_eq!(retried.p_digest(), expected.p_digest);
        assert_eq!(retried.p_sequence(), expected.p_sequence);
        assert_eq!(retried.target_head(), &expected.target_head);
        let confirmed = cold
            .commit_replay_finality_bytes_v1(
                &retried,
                &expected.original_proof,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert!(confirmed.belongs_to_application(&cold));
        assert_eq!(confirmed.head(), &expected.target_head);
        assert_eq!(confirmed.commit_sequence(), expected.target_state.sequence);
        assert_eq!(
            cold.confirmed_replay_head_v1().unwrap(),
            expected.target_head
        );
        assert_historical_continuation_crash_state_v1(&path, &expected, true, true);
    }
}
