type CheckpointCaseV4 = (
    tempfile::TempDir,
    super::EpochCheckpointPreparationRuntimeV4<Watermark, Watermark>,
    Key,
);

#[inline(never)]
fn checkpoint_prepare_begin_v4(case: Box<OrdinaryCutoffCaseV3>) -> Box<CheckpointCaseV4> {
    let (directory, owner, key, _) = *case;
    let owner = owner.into_checkpoint_preparation_v4().unwrap();
    Box::new((directory, owner, key))
}

#[inline(never)]
fn checkpoint_prepare_execute_v4(case: Box<CheckpointCaseV4>) -> Box<CheckpointCaseV4> {
    let (directory, mut owner, key) = *case;
    let inner = owner.inner.as_ref().unwrap();
    let selection = inner
        .runtime
        .application
        .compute_later_epoch_selection_v1(trnm_native_application::HeightV0::new(15))
        .unwrap();
    let commitment = selection.next_epoch_commitment().id();
    let wrong = trnm_consensus_types::NextEpochCommitmentHash::new([0xd5; 32]);
    assert_ne!(wrong, commitment);
    let bad = application_child_proposal_v4(inner, Some(wrong));
    bad.verify(
        inner.runtime.edge.new_validator_set(),
        None,
        inner.runtime.edge.new_parameters(),
        inner
            .prepared
            .last()
            .unwrap()
            .prepared
            .header()
            .unwrap()
            .timestamp_ms(),
        &trnm_consensus_crypto::StrictEd25519Verifier,
    )
    .unwrap();
    let good = application_child_proposal_v4(inner, Some(commitment));
    assert_eq!(good.block().header().height().get(), 18);
    let paths = [
        inner.runtime.application.path().to_path_buf(),
        inner.runtime.journal.path_v1().to_path_buf(),
        inner.runtime.ordinary.path().to_path_buf(),
        inner.runtime.checkpoint_store.database_path().to_path_buf(),
    ];
    let before: Vec<_> = paths.iter().map(|p| sqlite_logical_image_v3(p)).collect();
    let calls = key.calls;
    let error = owner.execute_checkpoint_proposal_v4(bad).unwrap_err();
    assert!(error
        .to_string()
        .contains("checkpoint commitment differs from actual cutoff selection"));
    assert_eq!(key.calls, calls);
    assert!(
        owner.inner.is_some(),
        "read-only refusal must preserve the real owner"
    );
    for (path, expected) in paths.iter().zip(before) {
        assert!(
            sqlite_logical_image_v3(path) == expected,
            "bad commitment wrote {}",
            path.display()
        );
    }
    owner.execute_checkpoint_proposal_v4(good.clone()).unwrap();
    assert_eq!(key.calls, calls, "P/Valid is not a key call");
    assert!(owner
        .execute_checkpoint_proposal_v4(good)
        .unwrap_err()
        .to_string()
        .contains("checkpoint preparation phase"));
    let inner = owner.inner.as_ref().unwrap();
    let pending = &inner
        .runtime
        .pending_epoch_commit
        .as_ref()
        .unwrap()
        .prepared;
    let read = inner
        .runtime
        .application
        .confirm_prepared_epoch_execution_v1(pending)
        .unwrap();
    let header = read.prepared().header().unwrap();
    assert_eq!(header.block_kind(), BlockKind::EpochCheckpoint);
    assert_eq!(header.next_epoch_commitment_hash(), Some(commitment));
    assert_eq!(read.commit_sequence(), None);
    assert_eq!(
        inner
            .runtime
            .application
            .confirmed_committed_head_v0()
            .unwrap(),
        *selection.cutoff_head()
    );
    let safety = inner
        .runtime
        .journal
        .fresh_read_v1(inner.runtime.pin)
        .unwrap();
    assert_eq!(safety.state_v1(), inner.runtime.driver.state());
    assert!(safety
        .transition_context_v1()
        .native_valid_transition()
        .is_some());
    assert!(
        matches!(inner.runtime.driver.state().pending_sign(), Some(trnm_consensus_core::SignIntent::Vote { block_id, .. }) if *block_id == header.id())
    );
    let completed: Vec<_> = inner
        .runtime
        .driver
        .state()
        .payload_validation_completions()
        .iter()
        .filter(|p| p.id().block_id() == header.id())
        .collect();
    assert_eq!(completed.len(), 1);
    let artifact = completed[0].result().artifact_ref().unwrap();
    assert_eq!(
        artifact.source_artifact_checksum(),
        read.artifact_checksum()
    );
    assert_eq!(
        artifact.overlay().overlay_checksum(),
        read.overlay_checksum()
    );
    assert_eq!(artifact.overlay().parent_block_id(), header.parent_id());
    Box::new((directory, owner, key))
}

#[inline(never)]
fn checkpoint_prepare_signed_v4(case: Box<CheckpointCaseV4>) -> Box<CheckpointCaseV4> {
    let (directory, mut owner, mut key) = *case;
    assert!(owner.prepared_checkpoint_cut_v4().is_err());
    let inner = owner.inner.as_ref().unwrap();
    let expected_header = inner
        .runtime
        .pending_epoch_commit
        .as_ref()
        .unwrap()
        .prepared
        .header()
        .unwrap();
    let original_p = inner
        .runtime
        .pending_epoch_commit
        .as_ref()
        .unwrap()
        .prepared
        .p_digest();
    let cutoff = inner.runtime.checkpoint.fields().application;
    let original_signer = inner.runtime.checkpoint.fields().ordinary.unwrap();
    let calls = key.calls;
    let (mut owner, vote) = owner.sign_checkpoint_vote_v4(&mut key).unwrap();
    assert_eq!(key.calls, calls + 1);
    let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else {
        panic!("checkpoint must release its real Vote")
    };
    assert_eq!(vote.block_id(), expected_header.id());
    let cut = owner.prepared_checkpoint_cut_v4().unwrap();
    assert_eq!(cut.fields().application, cutoff);
    assert_eq!(
        cut.fields().ordinary.unwrap().sequence,
        original_signer.sequence + 2
    );
    let inner = owner.inner.as_mut().unwrap();
    assert_eq!(inner.prepared.len(), 3);
    assert_eq!(inner.prepared[2].prepared.p_digest(), original_p);
    for (index, p) in inner.prepared.iter().enumerate() {
        assert_eq!(
            p.prepared.header().unwrap().height().get(),
            16 + index as u64
        );
        assert_eq!(
            inner
                .runtime
                .application
                .confirm_prepared_epoch_execution_v1(&p.prepared)
                .unwrap()
                .commit_sequence(),
            None
        );
    }
    assert!(inner.runtime.driver.state().pending_sign().is_none());
    assert_eq!(
        inner
            .runtime
            .driver
            .state()
            .application_applied()
            .height()
            .get(),
        15
    );
    assert_eq!(
        inner.runtime.driver.state().finalized(),
        inner.runtime.driver.state().application_applied()
    );
    assert_eq!(
        inner
            .runtime
            .journal
            .fresh_read_v1(inner.runtime.pin)
            .unwrap()
            .state_v1(),
        inner.runtime.driver.state()
    );
    inner.runtime.checkpoint_store.confirm_exact(&cut).unwrap();
    Box::new((directory, owner, key))
}

#[inline(never)]
fn checkpoint_prepare_sign_v4(case: Box<CheckpointCaseV4>) {
    let (_directory, owner, mut key) = *checkpoint_prepare_signed_v4(case);
    let calls = key.calls;
    assert!(owner.sign_checkpoint_vote_v4(&mut key).is_err());
    assert_eq!(key.calls, calls, "duplicate phase must never call the key");
}

#[test]
fn actual_epoch_checkpoint_preparation_uses_real_cutoff_before_valid_and_vote_v4() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    checkpoint_prepare_sign_v4(checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(
        cutoff,
    )));
}

include!("epoch_pre_handoff_v5_tests.inc");
