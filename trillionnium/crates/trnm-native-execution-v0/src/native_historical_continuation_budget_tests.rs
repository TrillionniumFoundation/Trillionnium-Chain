// Shared proof-meter regression for the genuine nonempty C33 continuation.

#[test]
fn historical_continuation_real_proof_meter_failure_is_atomic_and_retry_is_not_double_counted() {
    use trnm_consensus_types::Cev0AdmissionBudgetV0;

    let directory = tempfile::tempdir().unwrap();
    let sender_path = directory.path().join("sender.sqlite3");
    let receiver_path = directory.path().join("receiver.sqlite3");
    let mut fixture = build_nonempty_historical_replay_fixture_with_continuation(
        &sender_path,
        &receiver_path,
        &[],
    );
    let c33 = commit_genuine_c33_continuation(&sender_path, fixture.continuation.take().unwrap());
    let owner =
        DurableNativeApplicationV0::open(&receiver_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let anchor = owner
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    let base = owner
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let installed = owner.install_historical_replay_base_v1(&base).unwrap();
    let request = historical_continuation_request(&c33.sender_request, installed.target_head());
    let prepared = owner
        .prepare_replay_execution_v1(&request, &c33.header)
        .unwrap();
    let before = historical_continuation_counts(&receiver_path);
    let bytes_before = std::fs::read(&receiver_path).unwrap();

    // Measure the genuine proof while the shared aggregate meter is zero.
    let mut probe = Cev0AdmissionBudgetV0::protocol_v0();
    let probe_guard = DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(0);
    let error = match owner.commit_replay_finality_bytes_v1(
        &prepared,
        &c33.original_finality_cev0,
        &mut probe,
    ) {
        Ok(_) => panic!("aggregate zero must reject the genuine proof"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("replay aggregate proof work budget"));
    drop(probe_guard);
    let proof_work = probe.signature_work();
    assert!(proof_work > 0);
    assert_eq!(historical_continuation_counts(&receiver_path), before);
    assert_eq!(std::fs::read(&receiver_path).unwrap(), bytes_before);

    let mut insufficient = Cev0AdmissionBudgetV0::protocol_v0();
    let insufficient_guard =
        DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(proof_work - 1);
    let error = match owner.commit_replay_finality_bytes_v1(
        &prepared,
        &c33.original_finality_cev0,
        &mut insufficient,
    ) {
        Ok(_) => panic!("one missing aggregate work unit must reject"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("replay aggregate proof work budget"));
    drop(insufficient_guard);
    assert_eq!(insufficient.signature_work(), proof_work);
    assert_eq!(historical_continuation_counts(&receiver_path), before);
    assert_eq!(std::fs::read(&receiver_path).unwrap(), bytes_before);

    let sufficient_guard =
        DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(proof_work);
    let mut admitted_budget = Cev0AdmissionBudgetV0::protocol_v0();
    admitted_budget.charge_signature_work(7).unwrap();
    let committed = owner.commit_replay_finality_bytes_v1(
        &prepared,
        &c33.original_finality_cev0,
        &mut admitted_budget,
    );
    assert_eq!(admitted_budget.signature_work(), proof_work + 7);
    drop(sufficient_guard);
    let committed = committed.unwrap();
    let sequence = committed.commit_sequence();
    let retry_guard =
        DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(proof_work);
    let mut retry_budget = Cev0AdmissionBudgetV0::protocol_v0();
    retry_budget.charge_signature_work(9).unwrap();
    let retry = owner
        .commit_replay_finality_bytes_v1(&prepared, &c33.original_finality_cev0, &mut retry_budget)
        .unwrap();
    drop(retry_guard);
    assert_eq!(retry.commit_sequence(), sequence);
    assert_eq!(retry_budget.signature_work(), proof_work + 9);
    assert_eq!(historical_continuation_counts(&receiver_path).2, 1);
    let committed_head = committed.head().clone();
    let committed_bytes = std::fs::read(&receiver_path).unwrap();
    let cold_insufficient =
        DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(proof_work - 1);
    let error = owner
        .confirmed_replay_head_v1()
        .expect_err("fresh proof audit must use the aggregate cap");
    assert!(format!("{error:#}").contains("replay original finality"));
    drop(owner);
    assert!(DurableNativeApplicationV0::open_historical_replay_v1(
        &receiver_path,
        native_checkpoint_fixture_config_v1(),
    )
    .is_err());
    drop(cold_insufficient);
    assert_eq!(std::fs::read(&receiver_path).unwrap(), committed_bytes);
    let cold_sufficient =
        DurableNativeApplicationV0::narrow_replay_proof_budget_for_test_v1(proof_work);
    let cold = DurableNativeApplicationV0::open_historical_replay_v1(
        &receiver_path,
        native_checkpoint_fixture_config_v1(),
    )
    .unwrap();
    assert_eq!(cold.confirmed_replay_head_v1().unwrap(), committed_head);
    assert_eq!(
        historical_continuation_counts(&receiver_path),
        (sequence, 1, 1)
    );
    drop(cold_sufficient);
}
