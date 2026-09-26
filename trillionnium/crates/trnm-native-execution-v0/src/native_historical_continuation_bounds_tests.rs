// SQL-screen-only coverage for schema12 continuation bounds.  The real C18
// fixture is installed once; every mutation below is inert and is rejected
// before any continuation authority or blob decoding is attempted.

fn continuation_bounds_seed_v1() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    i64,
    [u8; 32],
    trnm_native_application::ApplicationHeadV0,
) {
    let seed = tempfile::tempdir().unwrap();
    let sender = seed.path().join("sender.sqlite3");
    let receiver = seed.path().join("receiver.sqlite3");
    let fixture = build_nonempty_historical_replay_fixture(&sender, &receiver);
    let app =
        DurableNativeApplicationV0::open(&receiver, native_checkpoint_fixture_config_v1()).unwrap();
    let anchor = app
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    let prepared = app
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let confirmed = app.install_historical_replay_base_v1(&prepared).unwrap();
    let input_digest = confirmed.input_digest();
    let target_head = confirmed.target_head().clone();
    drop(prepared);
    drop(anchor);
    drop(app);
    let connection = rusqlite::Connection::open(&receiver).unwrap();
    let legacy: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM native_durable_execution_p_v0)
                    + (SELECT COUNT(*) FROM native_durable_execution_p_v1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (seed, receiver, legacy, input_digest, target_head)
}

fn add_screen_only_p_rows_v1(
    connection: &rusqlite::Connection,
    start: u8,
    count: usize,
    status: i64,
    with_proofs: bool,
) {
    for offset in 0..count {
        let mut block = [0u8; 32];
        block[0] = start.wrapping_add(offset as u8);
        let p_sequence = (offset as u64 + 1).to_be_bytes();
        let commit_sequence = (offset as u64 + 1).to_be_bytes();
        let commit_id = [block[0]; 32];
        connection
            .execute(
                "INSERT INTO native_replay_execution_p_v1
                 (block_id,base_digest,p_sequence,status,parent_kind,parent_head,parent_p_digest,header,
                  artifact,artifact_digest,snapshot,snapshot_digest,commands,commands_digest,nonces,
                  nonces_digest,lifecycle,lifecycle_digest,p_digest,commit_sequence,commit_id)
                 VALUES (?1,zeroblob(32),?2,?3,0,zeroblob(104),NULL,zeroblob(1),
                         zeroblob(1),zeroblob(32),zeroblob(1),zeroblob(32),zeroblob(4),zeroblob(32),
                         zeroblob(4),zeroblob(32),zeroblob(1),zeroblob(32),zeroblob(32),?4,?5)",
                rusqlite::params![
                    block.as_slice(),
                    p_sequence.as_slice(),
                    status,
                    if status == 1 {
                        Some(commit_sequence.as_slice())
                    } else {
                        None
                    },
                    if status == 1 {
                        Some(commit_id.as_slice())
                    } else {
                        None
                    },
                ],
            )
            .unwrap();
        if with_proofs {
            let proof = vec![0u8; 8 * 1024 * 1024];
            let proof_digest: [u8; 32] = sha2::Sha256::digest(&proof).into();
            connection
                .execute(
                    "INSERT INTO native_replay_execution_finality_v1
                     (block_id,p_digest,commit_sequence,proof,proof_digest,record_digest)
                     VALUES (?1,zeroblob(32),?2,?3,?4,zeroblob(32))",
                    rusqlite::params![
                        block.as_slice(),
                        commit_sequence.as_slice(),
                        proof,
                        proof_digest.as_slice(),
                    ],
                )
                .unwrap();
        }
    }
}

#[test]
fn historical_continuation_sql_bounds_reject_combined_pending_and_proof_overflow() {
    let (seed, installed, legacy, input_digest, target_head) = continuation_bounds_seed_v1();
    assert!(legacy > 0);
    let assert_screen = |name: &str, expected: &str, mutation: &dyn Fn(&rusqlite::Connection)| {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{name}.sqlite3"));
        copy_later_store(&installed, &path);
        let owner = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        mutation(&connection);
        drop(connection);
        let error = owner
            .confirm_historical_replay_base_v1(input_digest, &target_head)
            .err()
            .expect("continuation SQL screen must reject the mutation");
        assert!(error.to_string().contains(expected), "{name}: {error:#}");
        drop(owner);
    };
    assert_screen(
        "pending-nine",
        "historical storage row count/profile: native_replay_execution_finality_v1",
        &|connection| add_screen_only_p_rows_v1(connection, 1, 9, 0, false),
    );
    assert_screen(
        "combined-129",
        "historical combined P row bound",
        &|connection| add_screen_only_p_rows_v1(connection, 1, 129 - legacy as usize, 1, false),
    );
    assert_screen(
        "proof-aggregate",
        "historical storage row count/profile: native_replay_execution_finality_v1",
        &|connection| add_screen_only_p_rows_v1(connection, 1, 9, 1, true),
    );
    assert_screen(
        "oversized-artifact",
        "historical storage SQL type/length/value screen: native_replay_execution_p_v1",
        &|connection| {
            connection
                .execute_batch("PRAGMA ignore_check_constraints=ON;")
                .unwrap();
            add_screen_only_p_rows_v1(connection, 1, 1, 0, false);
            connection
                .execute(
                    "UPDATE native_replay_execution_p_v1 SET artifact=zeroblob(16777217)",
                    [],
                )
                .unwrap();
        },
    );
    drop(seed);
}
