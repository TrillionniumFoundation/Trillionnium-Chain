// One genuine V5 source, with no SQL-built terminal Core state.
#[inline(never)]
fn finish_actual_outgoing_retirement_v6(case: Box<PreHandoffCaseV5>, watermark: Watermark) {
    let (_directory, mut owner, key) = *case;
    let predecessor = owner.settled_pre_handoff_cut_v5().unwrap();
    let inner = owner.inner.as_ref().unwrap();
    let ordinary_path = inner.runtime.ordinary.path().to_path_buf();
    let ordinary_profile = inner.runtime.ordinary.profile().clone();
    let native_cut = owner.receipt.as_ref().unwrap().committed_owner_cut_ref_v1();
    let old_retirement = *inner.runtime.retired.record_v1();
    let safety_before = sqlite_logical_image_v3(inner.runtime.journal.path_v1());
    let native_before = sqlite_logical_image_v3(inner.runtime.application.path());
    let calls = key.calls;
    assert!(watermark.0.lock().unwrap().1.is_none());
    let mut retired = owner.retire_outgoing_epoch_v6().unwrap();
    let cut = retired.confirm_retired_cut_v6().unwrap();
    assert_eq!(
        cut.fields().phase,
        super::EpochCheckpointPhaseV1::EpochRetiredNative13
    );
    assert_eq!(cut.fields().application, predecessor.fields().application);
    assert_eq!(
        cut.fields().target_safety,
        predecessor.fields().target_safety
    );
    assert_eq!(
        cut.fields().source_safety,
        Some(predecessor.fields().target_safety)
    );
    assert_eq!(cut.fields().generation, predecessor.fields().generation + 1);
    assert_eq!(cut.fields().edge.native_authorization_id, native_cut);
    assert!(cut.fields().ordinary.is_none());
    let actual = *retired.retired.record_v1();
    assert_eq!(watermark.0.lock().unwrap().1, Some(actual));
    let mut external_probe = watermark.clone();
    assert!(matches!(
        external_probe.load(actual.source_v1().scope()),
        Err(ExternalWatermarkErrorV0::InvalidPersistedState)
    ));
    assert_eq!(actual.source_v1(), watermark.0.lock().unwrap().0.unwrap());
    assert_eq!(
        cut.fields().retired.unwrap().retirement_record_checksum,
        actual.checksum_v1()
    );
    assert_ne!(
        actual.source_v1().journal_id(),
        old_retirement.source_v1().journal_id()
    );
    assert_eq!(*retired.source.incoming_retired.record_v1(), old_retirement);
    assert_eq!(
        key.calls, calls,
        "retirement must never invoke a role or ordinary key"
    );
    assert!(sqlite_logical_image_v3(retired.source.journal.path_v1()) == safety_before);
    assert!(sqlite_logical_image_v3(retired.source.application.path()) == native_before);

    // Both values are real owner-affine confirmations. The genuine incoming W
    // confirmation cannot replace the current N retirement, even in this epoch.
    std::mem::swap(
        &mut retired.retirement,
        &mut retired.source.incoming_retirement,
    );
    assert!(retired
        .join_target_v6()
        .unwrap_err()
        .to_string()
        .contains("incoming retired custody changed"));
    std::mem::swap(
        &mut retired.retirement,
        &mut retired.source.incoming_retirement,
    );
    assert_eq!(retired.confirm_retired_cut_v6().unwrap(), cut);

    // A stale source pin must be rejected by the actual journal read, before
    // returning the same terminal comparison. This test restores only a local
    // inert checkpoint copy; it never forges a Safety record or owner.
    let exact_source = retired.source.predecessor;
    let mut stale = *exact_source.fields();
    stale.target_safety.record_checksum[0] ^= 1;
    retired.source.predecessor = EpochNodeCheckpointV1::new(stale).unwrap();
    assert!(retired
        .join_target_v6()
        .unwrap_err()
        .to_string()
        .contains("exact settled journal9 cut"));
    retired.source.predecessor = exact_source;
    assert_eq!(retired.confirm_retired_cut_v6().unwrap(), cut);

    // Altering an inert expected native commitment cannot change the value
    // reconstructed from the actual receipt and owners.
    let mut wrong_target = *cut.fields();
    wrong_target.edge.native_authorization_id[0] ^= 1;
    assert_ne!(
        retired.join_target_v6().unwrap(),
        EpochNodeCheckpointV1::new(wrong_target).unwrap()
    );
    let external_path = retired.checkpoint_store.database_path().to_path_buf();
    let exact_bytes = cut.encode_canonical();
    let receipt = retired
        .source
        .application
        .recover_later_epoch_pre_handoff_v1(*retired.source.receipt.header().id().as_bytes())
        .unwrap();
    let intent = super::outgoing_intent_v6(&retired.source).unwrap();
    let native_path = retired.source.application.path().to_path_buf();
    let displaced = native_path.with_extension("retired-source-displaced");
    std::fs::rename(&native_path, &displaced).unwrap();
    std::fs::copy(&displaced, &native_path).unwrap();
    assert!(retired.confirm_retired_cut_v6().is_err());
    assert!(retired
        .confirm_retired_cut_v6()
        .unwrap_err()
        .to_string()
        .contains("owner fenced"));
    assert_eq!(key.calls, calls);
    drop(retired);
    let ordinary_error = SqliteSignerJournalV0::open_existing(
        &ordinary_path,
        ordinary_profile.clone(),
        watermark.clone(),
    )
    .err()
    .expect("retired schema must prevent ordinary reopen");
    assert!(
        matches!(
            ordinary_error,
            trnm_consensus_signer_journal::SignerJournalErrorV0::SchemaMismatch
        ),
        "retired local schema must reject before any ordinary lease: {ordinary_error}"
    );
    let mut signer = RetiredSqliteSignerJournalV1::open_existing_v1(
        &ordinary_path,
        ordinary_profile,
        watermark,
        actual,
        receipt.strict_context(),
        &intent,
    )
    .unwrap();
    assert_eq!(signer.confirm_retirement_v1().unwrap().record_v1(), &actual);
    let mut independent =
        super::SqliteEpochNodeCheckpointStoreV1::open_existing(&external_path, &cut).unwrap();
    assert_eq!(independent.load().unwrap().encode_canonical(), exact_bytes);
    assert_eq!(key.calls, calls);
}

#[test]
fn actual_epoch_outgoing_retirement_consumes_current_signer_after_native13_v6() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let watermark = live.3.new_watermark.clone();
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    let checkpoint = checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(cutoff));
    let first_seal = pre_handoff_seal_and_apply_v5(pre_handoff_begin_v5(checkpoint));
    let second_seal = pre_handoff_seal_and_apply_v5(first_seal);
    finish_actual_outgoing_retirement_v6(pre_handoff_commit_v5(second_seal), watermark);
}
