// Included in the genuine historical fixture namespace. The pause controls
// scheduling only; every checkpoint and install capability uses its real API.

struct HistoricalC8PreparationInputV1 {
    request: NativeBlockPreviewRequestV0,
    cutoff_finality: Vec<u8>,
    cutoff_parent: Vec<u8>,
}

fn historical_c8_preparation_input_v1(
    path: &std::path::Path,
) -> Box<HistoricalC8PreparationInputV1> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT evidence FROM native_epoch_edge_v1 WHERE checkpoint_height=?1",
            [8_u64.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let evidence = crate::epoch_recovery::EpochRecoveryEvidenceV1::decode(&bytes).unwrap();
    let executed = trnm_native_application::decode_native_executed_block_artifact_v0(
        &evidence.checkpoint_artifact,
    )
    .unwrap();
    let original = executed.request();
    Box::new(HistoricalC8PreparationInputV1 {
        request: NativeBlockPreviewRequestV0::new(
            original.chain_id().clone(),
            original.genesis_hash(),
            original.parent().clone(),
            original.height(),
            original.timestamp_ms(),
            original.active_validator_set_id(),
            original.transactions().to_vec(),
        )
        .unwrap(),
        cutoff_finality: evidence.cutoff_finality,
        cutoff_parent: evidence.cutoff_parent,
    })
}

fn prepare_historical_c8_at_view12_v1(
    owner: &DurableNativeApplicationV0,
    input: &HistoricalC8PreparationInputV1,
) -> Result<(), String> {
    let config = native_checkpoint_fixture_config_v1();
    owner
        .prepare_native_poco_checkpoint_v0(
            &input.request,
            View::new(12),
            config.validator_set_v0().validators()[3].id(),
            &input.cutoff_finality,
            &input.cutoff_parent,
        )
        .map(|prepared| {
            assert_eq!(prepared.header().height().get(), 8);
            assert_eq!(prepared.header().view(), View::new(12));
        })
        .map_err(|error| {
            error
                .downcast_ref::<crate::NativeApplicationExecutionErrorV0>()
                .map_or_else(|| error.to_string(), |error| error.field().to_owned())
        })
}

#[test]
#[inline(never)]
fn historical_install_serializes_real_checkpoint_preparation_and_rejects_late_write() {
    use crate::poco_checkpoint::preparation_lock_test_v1::{arm, Stage};
    use trnm_consensus_types::Cev0AdmissionBudgetV0;

    let directory = tempfile::tempdir().unwrap();
    let sender_path = directory.path().join("sender.sqlite3");
    let receiver_path = directory.path().join("receiver.sqlite3");
    let fixture = build_nonempty_historical_replay_fixture(&sender_path, &receiver_path);
    let input = historical_c8_preparation_input_v1(&receiver_path);

    // Prove the exact historical recovery request is accepted while schema10
    // is current. Pause its actual write path and observe the held owner lock.
    let positive_path = directory.path().join("checkpoint-first.sqlite3");
    copy_later_store(&receiver_path, &positive_path);
    let positive =
        DurableNativeApplicationV0::open(&positive_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    std::thread::scope(|scope| {
        let pause = arm(positive.path(), Stage::BeforeWrite);
        let worker = scope.spawn(|| prepare_historical_c8_at_view12_v1(&positive, &input));
        pause.wait_reached();
        assert!(positive.legacy_preparation_lock_held_for_test_v1());
        pause.release();
        worker.join().unwrap().unwrap();
    });
    let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open_existing(
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&positive_path),
    )
    .unwrap();
    assert_eq!(journal.replay_records().unwrap().len(), 2);
    assert!(!journal.is_halted().unwrap());
    assert_eq!(
        historical_fixture_state(&positive_path),
        fixture.source_state
    );
    drop(positive);

    let receiver =
        DurableNativeApplicationV0::open(&receiver_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let anchor = receiver
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    let prepared = receiver
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let journal_path =
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&receiver_path);
    let journal_before = std::fs::read(&journal_path).unwrap();
    let rows_before = historical_retained_rows(&receiver_path);
    std::thread::scope(|scope| {
        let pause = arm(receiver.path(), Stage::BeforeLock);
        let worker = scope.spawn(|| prepare_historical_c8_at_view12_v1(&receiver, &input));
        pause.wait_reached();
        assert!(!receiver.legacy_preparation_lock_held_for_test_v1());
        let installed = receiver
            .install_historical_replay_base_v1(&prepared)
            .unwrap();
        assert_eq!(installed.target_head(), prepared.target_head());
        pause.release();
        assert_eq!(worker.join().unwrap().unwrap_err(), "schema.exact");
    });
    assert_eq!(std::fs::read(&journal_path).unwrap(), journal_before);
    assert_eq!(historical_retained_rows(&receiver_path), rows_before);
    assert_eq!(
        historical_fixture_state(&receiver_path).sequence,
        fixture.source_state.sequence + 1
    );
    assert_eq!(
        receiver
            .confirm_historical_replay_base_v1(prepared.input_digest(), prepared.target_head())
            .unwrap()
            .target_head(),
        prepared.target_head()
    );
}
