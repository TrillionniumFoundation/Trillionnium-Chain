use crate::*;

fn hash(byte: u8) -> Hash32V0 {
    Hash32V0::new([byte; 32])
}

fn block_id(byte: u8) -> BlockIdV0 {
    BlockIdV0::new([byte; 32]).unwrap()
}

fn state_root(byte: u8) -> StateRootV0 {
    StateRootV0::new([byte; 32]).unwrap()
}

fn commit_id(byte: u8) -> ApplicationCommitIdV0 {
    ApplicationCommitIdV0::new([byte; 32]).unwrap()
}

fn set_id(byte: u8) -> ValidatorSetIdV0 {
    ValidatorSetIdV0::new([byte; 32]).unwrap()
}

fn validator_set(id: u8, suffix: &str) -> NativeValidatorSetV0 {
    NativeValidatorSetV0::new(
        set_id(id),
        vec![
            NativeValidatorV0::new(format!("a-{suffix}"), [id; 32], 25).unwrap(),
            NativeValidatorV0::new(format!("b-{suffix}"), [id + 1; 32], 25).unwrap(),
            NativeValidatorV0::new(format!("c-{suffix}"), [id + 2; 32], 25).unwrap(),
            NativeValidatorV0::new(format!("d-{suffix}"), [id + 3; 32], 25).unwrap(),
        ],
    )
    .unwrap()
}

fn parent_head() -> ApplicationHeadV0 {
    ApplicationHeadV0::new(HeightV0::GENESIS, block_id(1), state_root(2), commit_id(3))
}

fn execution_request() -> NativeBlockExecutionRequestV0 {
    NativeBlockExecutionRequestV0::new(
        ChainIdV0::new("trnm-test").unwrap(),
        GenesisHashV0::new([4; 32]).unwrap(),
        parent_head(),
        block_id(5),
        HeightV0::new(1),
        42,
        set_id(6),
        vec![b"signed-transaction".to_vec()],
        NativeExpectedBlockCommitmentsV0::new(
            hash(7),
            state_root(8),
            ReceiptsRootV0::new([9; 32]).unwrap(),
            hash(10),
        )
        .unwrap(),
    )
    .unwrap()
}

fn execution_receipt() -> NativeExecutionReceiptV0 {
    let event = NativeEventV0::new(
        "transfer",
        vec![
            NativeEventAttributeV0::new("amount", "7").unwrap(),
            NativeEventAttributeV0::new("asset", "TRNM").unwrap(),
        ],
    )
    .unwrap();
    NativeExecutionReceiptV0::new(0, hash(11), 12, 13, vec![event], hash(14)).unwrap()
}

fn executed_block() -> NativeExecutedBlockV0 {
    NativeExecutedBlockV0::new(
        execution_request(),
        hash(7),
        state_root(8),
        ReceiptsRootV0::new([9; 32]).unwrap(),
        hash(10),
        vec![execution_receipt()],
    )
    .unwrap()
}

#[test]
fn executed_artifact_codec_round_trips_complete_value_exactly() {
    let executed = executed_block();
    let encoded = encode_native_executed_block_artifact_v0(&executed).unwrap();
    assert!(encoded.starts_with(NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0));
    assert_eq!(
        &encoded[NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0.len()
            ..NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0.len() + 8],
        &NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0.to_be_bytes()
    );
    let decoded = decode_native_executed_block_artifact_v0(&encoded).unwrap();
    assert_eq!(decoded, executed);
    assert_eq!(
        encode_native_executed_block_artifact_v0(&decoded).unwrap(),
        encoded
    );
}

#[test]
fn executed_artifact_codec_rejects_domain_version_truncation_and_trailing_bytes() {
    let encoded = encode_native_executed_block_artifact_v0(&executed_block()).unwrap();

    let mut wrong_domain = encoded.clone();
    wrong_domain[0] ^= 1;
    assert_eq!(
        decode_native_executed_block_artifact_v0(&wrong_domain)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::NotCanonical
    );

    let mut wrong_version = encoded.clone();
    wrong_version[NATIVE_EXECUTED_BLOCK_ARTIFACT_DOMAIN_V0.len() + 7] = 1;
    assert_eq!(
        decode_native_executed_block_artifact_v0(&wrong_version)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::NotCanonical
    );

    for truncated in [0, 1, encoded.len() - 1] {
        assert_eq!(
            decode_native_executed_block_artifact_v0(&encoded[..truncated])
                .unwrap_err()
                .code(),
            NativeBoundaryErrorCodeV0::NotCanonical
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_native_executed_block_artifact_v0(&trailing)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::NotCanonical
    );
}

#[test]
fn native_execution_and_commit_are_exactly_bound() {
    let executed = executed_block();
    let request = NativeApplicationCommitRequestV0::new(executed);
    let target = validator_set(20, "target");
    let transition =
        NativeValidatorSetTransitionV0::new(set_id(6), target, HeightV0::new(3)).unwrap();
    let head = ApplicationHeadV0::new(HeightV0::new(1), block_id(5), state_root(8), commit_id(15));
    let committed =
        NativeApplicationCommitResultV0::new(&request, head.clone(), 1, Some(transition)).unwrap();
    assert_eq!(committed.request(), &request);
    assert_eq!(committed.executed(), request.executed());
    assert_eq!(committed.head(), &head);
    assert_eq!(committed.durable_sequence(), 1);
    assert_eq!(
        committed.validator_transition().unwrap().current_set_id(),
        set_id(6)
    );
}

#[test]
fn commitment_or_receipt_mismatch_is_rejected() {
    let wrong_root = NativeExecutedBlockV0::new(
        execution_request(),
        hash(7),
        state_root(99),
        ReceiptsRootV0::new([9; 32]).unwrap(),
        hash(10),
        vec![execution_receipt()],
    )
    .unwrap_err();
    assert_eq!(
        wrong_root.code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );

    let wrong_receipt_count = NativeExecutedBlockV0::new(
        execution_request(),
        hash(7),
        state_root(8),
        ReceiptsRootV0::new([9; 32]).unwrap(),
        hash(10),
        Vec::new(),
    )
    .unwrap_err();
    assert_eq!(
        wrong_receipt_count.code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
}

#[test]
fn deterministic_invalid_codes_are_canonical() {
    let request = execution_request();
    let invalid = NativeDeterministicInvalidV0::new(&request, "receipt_root_mismatch").unwrap();
    assert_eq!(invalid.request(), &request);
    assert_eq!(invalid.block_id(), request.block_id());
    assert_eq!(invalid.height(), request.height());
    assert_eq!(invalid.code(), "receipt_root_mismatch");
    assert_eq!(
        NativeDeterministicInvalidV0::new(&request, "Not Canonical")
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::NotCanonical
    );
}

#[test]
fn event_attributes_and_validator_sets_require_canonical_order() {
    let unordered = NativeEventV0::new(
        "event",
        vec![
            NativeEventAttributeV0::new("z", "1").unwrap(),
            NativeEventAttributeV0::new("a", "2").unwrap(),
        ],
    )
    .unwrap_err();
    assert_eq!(unordered.code(), NativeBoundaryErrorCodeV0::NotCanonical);

    let unordered_set = NativeValidatorSetV0::new(
        set_id(30),
        vec![
            NativeValidatorV0::new("z", [1; 32], 1).unwrap(),
            NativeValidatorV0::new("a", [2; 32], 1).unwrap(),
        ],
    )
    .unwrap_err();
    assert_eq!(
        unordered_set.code(),
        NativeBoundaryErrorCodeV0::NotCanonical
    );
}

#[test]
fn genesis_result_binds_root_height_and_validator_set() {
    let validators = validator_set(40, "genesis");
    let request = NativeApplicationGenesisRequestV0::new(
        ChainIdV0::new("trnm-genesis").unwrap(),
        GenesisHashV0::new([41; 32]).unwrap(),
        hash(42),
        hash(43),
        state_root(44),
        validators.clone(),
    )
    .unwrap();
    let head = ApplicationHeadV0::new(
        HeightV0::GENESIS,
        block_id(45),
        state_root(44),
        commit_id(46),
    );
    let result =
        NativeApplicationGenesisResultV0::new(&request, head.clone(), validators.set_id()).unwrap();
    assert_eq!(result.request(), &request);
    assert_eq!(result.head(), &head);
    assert_eq!(result.active_validator_set_id(), validators.set_id());
}

fn finalization_head(height: u64, seed: u8) -> ApplicationHeadV0 {
    ApplicationHeadV0::new(
        HeightV0::new(height),
        block_id(seed),
        state_root(seed.wrapping_add(1)),
        commit_id(seed.wrapping_add(2)),
    )
}

fn finalization_intent(
    parent: ApplicationHeadV0,
    target: ApplicationHeadV0,
    seed: u8,
) -> NativeFinalizationIntentV0 {
    NativeFinalizationIntentV0::new(
        parent,
        target,
        hash(seed),
        hash(seed.wrapping_add(1)),
        hash(seed.wrapping_add(2)),
        hash(seed.wrapping_add(3)),
    )
    .unwrap()
}

fn finalization_readback(
    intent: NativeFinalizationIntentV0,
    durable_sequence: u64,
    seed: u8,
) -> NativeFinalizationApplyReadbackV0 {
    NativeFinalizationApplyReadbackV0::new(
        intent.clone(),
        intent.target().clone(),
        intent.target().state_root(),
        hash(seed),
        durable_sequence,
    )
    .unwrap()
}

#[test]
fn finalization_queue_rejects_skips_reorders_and_root_drift_without_mutation() {
    let h0 = finalization_head(0, 101);
    let h1 = finalization_head(1, 111);
    let h2 = finalization_head(2, 121);
    let h3 = finalization_head(3, 131);
    let i1 = finalization_intent(h0.clone(), h1.clone(), 141);
    let i2 = finalization_intent(h1.clone(), h2.clone(), 151);
    let i3 = finalization_intent(h2.clone(), h3.clone(), 161);
    let mut queue = NativeFinalizationQueueV0::new(h0.clone(), 8).unwrap();
    let before_skip = queue.clone();
    assert_eq!(
        queue.enqueue(i2.clone()).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::NonContiguous
    );
    assert_eq!(queue, before_skip, "a skipped enqueue changed queue state");
    assert_eq!(
        queue.enqueue(i1.clone()).unwrap(),
        NativeFinalizationEnqueueOutcomeV0::Queued
    );
    assert_eq!(
        queue.enqueue(i2.clone()).unwrap(),
        NativeFinalizationEnqueueOutcomeV0::Queued
    );
    assert_eq!(
        queue.enqueue(i3.clone()).unwrap(),
        NativeFinalizationEnqueueOutcomeV0::Queued
    );
    let before = queue.clone();
    assert_eq!(
        queue
            .acknowledge_front(finalization_readback(i2.clone(), 2, 171))
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::NonContiguous
    );
    assert_eq!(queue, before, "a skipped front changed queue state");

    let before_bad_root = queue.clone();
    assert_eq!(
        NativeFinalizationApplyReadbackV0::new(
            i1.clone(),
            i1.target().clone(),
            state_root(0xee),
            hash(181),
            1,
        )
        .unwrap_err()
        .code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
    assert_eq!(
        queue, before_bad_root,
        "a post-state-root drift changed queue state"
    );

    assert!(matches!(
        queue.acknowledge_front(finalization_readback(i1.clone(), 1, 181)),
        Ok(NativeFinalizationApplyOutcomeV0::NewlyCommitted(_))
    ));
    assert!(matches!(
        queue.acknowledge_front(finalization_readback(i2.clone(), 2, 191)),
        Ok(NativeFinalizationApplyOutcomeV0::NewlyCommitted(_))
    ));
    assert!(matches!(
        queue.acknowledge_front(finalization_readback(i3.clone(), 3, 201)),
        Ok(NativeFinalizationApplyOutcomeV0::NewlyCommitted(_))
    ));
    assert_eq!(queue.committed_head(), &h3);
    assert!(queue.pending().is_empty());
    assert_eq!(
        queue.reconcile(&i2).unwrap(),
        NativeFinalizationRetryDispositionV0::ExactCommitted(finalization_readback(i2, 2, 191))
    );
}

#[test]
fn finalization_queue_rejects_conflicting_duplicates_and_preserves_exact_replay() {
    let h0 = finalization_head(0, 211);
    let h1 = finalization_head(1, 221);
    let intent = finalization_intent(h0.clone(), h1, 231);
    let mut queue = NativeFinalizationQueueV0::new(h0, 2).unwrap();
    assert_eq!(
        queue.enqueue(intent.clone()).unwrap(),
        NativeFinalizationEnqueueOutcomeV0::Queued
    );
    assert_eq!(
        queue.enqueue(intent.clone()).unwrap(),
        NativeFinalizationEnqueueOutcomeV0::AlreadyQueued
    );
    let conflicting = NativeFinalizationIntentV0::new(
        intent.parent().clone(),
        intent.target().clone(),
        hash(241),
        intent.overlay_checksum(),
        intent.body_digest(),
        intent.jmt_plan_digest(),
    )
    .unwrap();
    assert_eq!(
        queue.enqueue(conflicting).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
    let readback = finalization_readback(intent.clone(), 1, 251);
    let first = queue.acknowledge_front(readback.clone()).unwrap();
    assert_eq!(
        first,
        NativeFinalizationApplyOutcomeV0::NewlyCommitted(readback.clone())
    );
    assert_eq!(
        queue.acknowledge_front(readback.clone()).unwrap(),
        NativeFinalizationApplyOutcomeV0::ExactReplay(readback.clone())
    );
    let conflicting_readback = NativeFinalizationApplyReadbackV0::new(
        readback.intent().clone(),
        readback.committed_head().clone(),
        readback.jmt_root(),
        hash(252),
        readback.durable_sequence(),
    )
    .unwrap();
    assert_eq!(
        queue
            .acknowledge_front(conflicting_readback)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
    assert_eq!(queue.history().len(), 1, "duplicate replay appended history");
}

#[test]
fn finalization_queue_retains_referenced_fork_and_reclaims_only_unreferenced_evidence() {
    let h0 = finalization_head(0, 31);
    let canonical_h1 = finalization_head(1, 41);
    let fork_h1 = finalization_head(1, 51);
    let fork_h2 = finalization_head(2, 61);
    let canonical = finalization_intent(h0.clone(), canonical_h1, 71);
    let losing = finalization_intent(h0, fork_h1.clone(), 81);
    let losing_child = finalization_intent(fork_h1, fork_h2, 91);
    let reference = hash(101);
    let mut queue = NativeFinalizationQueueV0::new(finalization_head(0, 31), 4).unwrap();
    queue.enqueue(canonical).unwrap();
    queue
        .retain_losing_fork(losing.clone(), reference)
        .unwrap();
    assert_eq!(
        queue.enqueue(losing).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::Duplicate,
        "a retained losing fork must never be promoted by retry"
    );
    queue
        .retain_losing_fork(losing_child, hash(102))
        .unwrap();
    assert_eq!(
        queue
            .reclaim_unreferenced_forks(&[reference, hash(102)])
            .unwrap(),
        0
    );
    assert_eq!(queue.forks().len(), 2);
    // Once the child reference is released, the child can be reclaimed first;
    // the parent remains protected by its own live reference.
    assert_eq!(queue.reclaim_unreferenced_forks(&[reference]).unwrap(), 1);
    assert_eq!(queue.forks().len(), 1);
    assert_eq!(queue.reclaim_unreferenced_forks(&[]).unwrap(), 1);
    assert!(queue.forks().is_empty());
}

#[test]
fn finalization_queue_reconciles_pending_and_fails_closed_for_unknown_sources() {
    let h0 = finalization_head(0, 41);
    let h1 = finalization_head(1, 51);
    let h2 = finalization_head(2, 61);
    let h3 = finalization_head(3, 91);
    let intent = finalization_intent(h0.clone(), h1.clone(), 71);
    let unknown = finalization_intent(h2, h3, 81);
    let mut queue = NativeFinalizationQueueV0::new(h0, 2).unwrap();
    queue.enqueue(intent.clone()).unwrap();
    assert_eq!(
        queue.reconcile(&intent).unwrap(),
        NativeFinalizationRetryDispositionV0::Pending
    );
    assert_eq!(
        queue.reconcile(&unknown).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::InvalidTransition
    );
    let before = queue.clone();
    assert_eq!(
        queue.enqueue(unknown).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::NonContiguous
    );
    assert_eq!(queue, before, "unknown retry altered the pending front");
}

#[test]
fn finalization_queue_bounds_and_sequence_regressions_are_atomic() {
    let h0 = finalization_head(0, 101);
    assert_eq!(
        NativeFinalizationQueueV0::new(h0.clone(), 0)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::ZeroValue
    );
    assert_eq!(
        NativeFinalizationQueueV0::new(h0.clone(), MAX_FINALIZATION_QUEUE_ENTRIES_V0 + 1)
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::TooMany
    );

    let h1 = finalization_head(1, 111);
    let h2 = finalization_head(2, 121);
    let i1 = finalization_intent(h0.clone(), h1.clone(), 131);
    let i2 = finalization_intent(h1, h2, 141);
    let mut queue = NativeFinalizationQueueV0::new(h0, 1).unwrap();
    queue.enqueue(i1.clone()).unwrap();
    let before_full = queue.clone();
    assert_eq!(
        queue.enqueue(i2.clone()).unwrap_err().code(),
        NativeBoundaryErrorCodeV0::TooMany
    );
    assert_eq!(queue, before_full);
    queue
        .acknowledge_front(finalization_readback(i1, 2, 151))
        .unwrap();
    queue.enqueue(i2.clone()).unwrap();
    let before_regression = queue.clone();
    assert_eq!(
        queue
            .acknowledge_front(finalization_readback(i2, 1, 161))
            .unwrap_err()
            .code(),
        NativeBoundaryErrorCodeV0::InvalidTransition
    );
    assert_eq!(queue, before_regression);
}

#[test]
fn finalization_intent_and_readback_reject_zero_or_non_successor_identity() {
    let h0 = finalization_head(0, 111);
    let same_height = finalization_head(0, 121);
    assert_eq!(
        NativeFinalizationIntentV0::new(
            h0.clone(),
            same_height,
            hash(131),
            hash(132),
            hash(133),
            hash(134),
        )
        .unwrap_err()
        .code(),
        NativeBoundaryErrorCodeV0::NonContiguous
    );
    let h1 = finalization_head(1, 141);
    let intent = NativeFinalizationIntentV0::new(
        h0,
        h1.clone(),
        Hash32V0::new([0; 32]),
        hash(151),
        hash(152),
        hash(153),
    )
    .unwrap_err();
    assert_eq!(intent.code(), NativeBoundaryErrorCodeV0::ZeroValue);
    let valid = finalization_intent(finalization_head(0, 161), h1, 171);
    assert_eq!(
        NativeFinalizationApplyReadbackV0::new(
            valid,
            finalization_head(1, 181),
            state_root(182),
            hash(183),
            1,
        )
        .unwrap_err()
        .code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
}

#[test]
fn snapshot_manifest_requires_contiguous_bounded_chunks() {
    let request = NativeSnapshotRequestV0::new(parent_head(), 1024).unwrap();
    let manifest = NativeSnapshotManifestV0::new(
        request.clone(),
        vec![
            NativeSnapshotChunkV0::new(0, 512, hash(50)).unwrap(),
            NativeSnapshotChunkV0::new(1, 128, hash(51)).unwrap(),
        ],
        hash(52),
    )
    .unwrap();
    assert_eq!(manifest.total_bytes(), 640);

    let gap = NativeSnapshotManifestV0::new(
        request,
        vec![NativeSnapshotChunkV0::new(1, 512, hash(53)).unwrap()],
        hash(54),
    )
    .unwrap_err();
    assert_eq!(gap.code(), NativeBoundaryErrorCodeV0::NonContiguous);
}

#[test]
fn state_proof_is_bound_to_an_exact_head_and_key() {
    let request = NativeStateProofRequestV0::new(parent_head(), b"account/alice".to_vec()).unwrap();
    let proof = NativeStateProofV0::new(
        request.clone(),
        NativeStateProofSchemeV0::JmtIcs23V0,
        Some(b"value".to_vec()),
        vec![1, 2, 3],
    )
    .unwrap();
    assert_eq!(proof.request(), &request);
    assert_eq!(proof.value(), Some(b"value".as_slice()));
}

#[test]
fn unavailable_result_retains_the_complete_exact_request() {
    let request = execution_request();
    let result = NativeBlockExecutionResultV0::unavailable(
        &request,
        NativeUnavailableReasonV0::HostResourceUnavailable,
    );
    let NativeBlockExecutionResultV0::Unavailable(unavailable) = result else {
        panic!("expected unavailable result");
    };
    assert_eq!(unavailable.request(), &request);
    assert_eq!(
        unavailable.reason(),
        NativeUnavailableReasonV0::HostResourceUnavailable
    );
}

#[test]
fn exact_recovery_rejects_rollback_and_head_substitution() {
    let minimum = NativeRecoveryWatermarksV0::new(5, 6, 7);
    let request = NativeApplicationRecoveryRequestV0::new(
        ChainIdV0::new("trnm-recovery").unwrap(),
        GenesisHashV0::new([60; 32]).unwrap(),
        hash(61),
        hash(62),
        parent_head(),
        minimum,
    )
    .unwrap();
    let exact = NativeApplicationRecoveryResultV0::new(
        &request,
        parent_head(),
        minimum,
        NativeRecoveryDispositionV0::Exact,
    )
    .unwrap();
    assert_eq!(exact.request(), &request);
    assert_eq!(exact.disposition(), NativeRecoveryDispositionV0::Exact);

    let rollback = NativeApplicationRecoveryResultV0::new(
        &request,
        parent_head(),
        NativeRecoveryWatermarksV0::new(4, 6, 7),
        NativeRecoveryDispositionV0::Exact,
    )
    .unwrap_err();
    assert_eq!(
        rollback.code(),
        NativeBoundaryErrorCodeV0::InvalidTransition
    );

    let substituted =
        ApplicationHeadV0::new(HeightV0::GENESIS, block_id(70), state_root(2), commit_id(3));
    let mismatch = NativeApplicationRecoveryResultV0::new(
        &request,
        substituted,
        minimum,
        NativeRecoveryDispositionV0::Exact,
    )
    .unwrap_err();
    assert_eq!(mismatch.code(), NativeBoundaryErrorCodeV0::BindingMismatch);
}

#[test]
fn replay_recovery_requires_the_exact_expected_head_without_ancestry_proof() {
    let minimum = NativeRecoveryWatermarksV0::new(5, 6, 7);
    let expected_head = ApplicationHeadV0::new(
        HeightV0::new(2),
        block_id(71),
        state_root(72),
        commit_id(73),
    );
    let request = NativeApplicationRecoveryRequestV0::new(
        ChainIdV0::new("trnm-replay-recovery").unwrap(),
        GenesisHashV0::new([74; 32]).unwrap(),
        hash(75),
        hash(76),
        expected_head.clone(),
        minimum,
    )
    .unwrap();

    let exact_replay = NativeApplicationRecoveryResultV0::new(
        &request,
        expected_head,
        minimum,
        NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 1 },
    )
    .unwrap();
    assert_eq!(
        exact_replay.disposition(),
        NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 1 }
    );

    let same_height_fork = ApplicationHeadV0::new(
        HeightV0::new(2),
        block_id(77),
        state_root(72),
        commit_id(73),
    );
    let same_height_error = NativeApplicationRecoveryResultV0::new(
        &request,
        same_height_fork,
        minimum,
        NativeRecoveryDispositionV0::ValidationReplayRequired { pending_records: 1 },
    )
    .unwrap_err();
    assert_eq!(
        same_height_error.code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );

    let lower_fork = ApplicationHeadV0::new(
        HeightV0::new(1),
        block_id(78),
        state_root(79),
        commit_id(80),
    );
    let lower_fork_error = NativeApplicationRecoveryResultV0::new(
        &request,
        lower_fork,
        minimum,
        NativeRecoveryDispositionV0::FinalizationReplayRequired { pending_records: 1 },
    )
    .unwrap_err();
    assert_eq!(
        lower_fork_error.code(),
        NativeBoundaryErrorCodeV0::BindingMismatch
    );
}

#[test]
fn block_height_and_payload_bounds_fail_closed() {
    let parent = parent_head();
    let commitments = NativeExpectedBlockCommitmentsV0::new(
        hash(80),
        state_root(81),
        ReceiptsRootV0::new([82; 32]).unwrap(),
        hash(83),
    )
    .unwrap();
    let wrong_height = NativeBlockExecutionRequestV0::new(
        ChainIdV0::new("trnm-test").unwrap(),
        GenesisHashV0::new([84; 32]).unwrap(),
        parent.clone(),
        block_id(85),
        HeightV0::new(2),
        0,
        set_id(86),
        Vec::new(),
        commitments,
    )
    .unwrap_err();
    assert_eq!(
        wrong_height.code(),
        NativeBoundaryErrorCodeV0::NonContiguous
    );

    let oversized_transaction = NativeBlockExecutionRequestV0::new(
        ChainIdV0::new("trnm-test").unwrap(),
        GenesisHashV0::new([84; 32]).unwrap(),
        parent,
        block_id(85),
        HeightV0::new(1),
        0,
        set_id(86),
        vec![vec![0; crate::application::MAX_BLOCK_BYTES_V0]],
        commitments,
    )
    .unwrap_err();
    assert_eq!(
        oversized_transaction.code(),
        NativeBoundaryErrorCodeV0::TooLong
    );
}
