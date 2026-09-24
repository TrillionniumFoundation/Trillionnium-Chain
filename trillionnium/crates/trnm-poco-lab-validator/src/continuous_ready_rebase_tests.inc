// Genuine Ready-only projection regressions. Included in continuous_runtime::tests.
fn ready_synced_rebase_fixture_v1() -> Box<(TakeoverPhaseHarnessV0, usize, SignedProposalV0)> {
    let lifetime = ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(2, 2, 4, 2).unwrap();
    let mut harness = takeover_phase_harness_with_profile_v0(4, lifetime, 2);
    let original = proposal_for_takeover_v0(&harness);
    let mut collector = ConsensusCertificateCollectorV0::new(
        harness.validator_set.clone(),
        MAXIMUM_COLLECTOR_COORDINATES_V0,
    )
    .unwrap();
    collector
        .register_qc_reference(harness.authorities[0].justify_v0().clone())
        .unwrap();
    for authority in &mut harness.authorities {
        collector
            .admit_timeout_vote(authority.begin_local_timeout_v0().unwrap())
            .unwrap();
    }
    let tc = collector
        .try_timeout_certificate(original.block().header().view())
        .unwrap()
        .unwrap();
    for authority in &mut harness.authorities {
        authority
            .advance_timeout_certificate_v0(tc.clone())
            .unwrap();
    }
    let next_view = harness.authorities[0].facts_v0().unwrap().current_view_v0();
    let receiver = harness
        .validator_set
        .validators()
        .iter()
        .position(|v| v.id() == leader_for(&harness.validator_set, next_view))
        .unwrap();
    assert!(harness.authorities[receiver]
        .sync_late_proposal_v1(UnboundProposalV0::from_signed(&original).unwrap(),)
        .unwrap());
    let before = harness.authorities[receiver].facts_v0().unwrap();
    assert_eq!(before.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
    assert_eq!(before.proposal_parent_block_id_v0(), original.block().id());
    assert_eq!(
        before.high_qc_v0().block_id(),
        original.block().header().parent_id()
    );
    assert!(
        !harness.authorities[receiver]
            .sync_late_proposal_v1(UnboundProposalV0::from_signed(&original).unwrap(),)
            .unwrap(),
        "exact Ready late-body replay is inert despite native parent ahead of QC"
    );
    assert_eq!(before, harness.authorities[receiver].facts_v0().unwrap());
    Box::new((harness, receiver, original))
}

fn ready_rebase_checkpoint_bytes_v1(path: &Path) -> Vec<u8> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    connection
        .query_row(
            "SELECT record FROM trnm_external_node_checkpoint_v0",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn ready_synced_rebase_preserves_child_and_allows_real_alternate_vote_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        let mut fixture = ready_synced_rebase_fixture_v1();
        let (harness, receiver, original) = &mut *fixture;
        let receiver = *receiver;
        let before = harness.authorities[receiver].facts_v0().unwrap();
        let key_calls = Arc::new(AtomicUsize::new(0));
        let producer = std::mem::replace(
            &mut harness.authorities[receiver].producer,
            ContinuousSignatureProducerV0(Box::new(ForbiddenSyncedSignatureProducerV1(
                Arc::clone(&key_calls),
            ))),
        );
        let proposal_producer = std::mem::replace(
            &mut harness.authorities[receiver].proposal_producer,
            ContinuousProposalSignatureProducerV0(Box::new(ForbiddenSyncedSignatureProducerV1(
                Arc::clone(&key_calls),
            ))),
        );
        assert!(harness.authorities[receiver]
            .proposal_witness_ready_v1()
            .unwrap());
        let after = harness.authorities[receiver].facts_v0().unwrap();
        assert_eq!(after.phase_v0(), PocoNodeLabAuthorityPhaseV0::Ready);
        assert_eq!(after.current_view_v0(), before.current_view_v0());
        assert_eq!(after.high_qc_v0(), before.high_qc_v0());
        assert_eq!(after.safety_revision_v0(), before.safety_revision_v0());
        assert_eq!(
            after.signer_watermark_sequence_v0(),
            before.signer_watermark_sequence_v0()
        );
        assert_eq!(
            after.signed_vote_intents_v0(),
            before.signed_vote_intents_v0()
        );
        assert_eq!(
            after.signed_timeout_intents_v0(),
            before.signed_timeout_intents_v0()
        );
        assert_eq!(
            after.checkpoint_generation_v0(),
            before.checkpoint_generation_v0() + 1
        );
        assert_eq!(
            after.proposal_parent_block_id_v0(),
            after.high_qc_v0().block_id()
        );
        assert_eq!(key_calls.load(Ordering::SeqCst), 0);
        // Repeated authoring readiness does not create another checkpoint generation.
        assert!(harness.authorities[receiver]
            .proposal_witness_ready_v1()
            .unwrap());
        assert_eq!(harness.authorities[receiver].facts_v0().unwrap(), after);
        let native_path = harness._temp.path().join(format!(
            "takeover-authority-{receiver:03}/application/application.sqlite3"
        ));
        let native = rusqlite::Connection::open_with_flags(
            native_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: u64 = native
            .query_row(
                "SELECT COUNT(*) FROM native_durable_execution_p_v0 WHERE block_id=?1",
                [original.block().id().as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "original synced child survives exact rebase");
        drop(native);
        harness.authorities[receiver].producer = producer;
        harness.authorities[receiver].proposal_producer = proposal_producer;
        let alternate = proposal_for_takeover_v0(harness);
        assert_eq!(
            alternate.block().header().height(),
            original.block().header().height()
        );
        assert_eq!(
            alternate.block().header().parent_id(),
            original.block().header().parent_id()
        );
        assert_ne!(alternate.block().id(), original.block().id());
        assert!(alternate.block().header().view() > original.block().header().view());
        let vote_calls = Arc::new(AtomicUsize::new(0));
        harness.authorities[receiver].producer =
            ContinuousSignatureProducerV0(Box::new(CountingSignatureProducerV0 {
                inner: LabEd25519SignatureProducer::new(harness.keys[receiver].clone()),
                calls: Arc::clone(&vote_calls),
            }));
        let vote = harness.authorities[receiver]
            .vote_proposal_v0(alternate.clone())
            .unwrap();
        assert_eq!(vote.block_id(), alternate.block().id());
        assert_eq!(vote_calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn ready_synced_rebase_cold_profile_keeps_actual_source_and_children_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        let mut fixture = ready_synced_rebase_fixture_v1();
        let (harness, receiver, original) = &mut *fixture;
        let receiver = *receiver;
        assert!(harness.authorities[receiver]
            .rebase_ready_parent_v1()
            .unwrap());
        let expected = harness.authorities[receiver].facts_v0().unwrap();
        let root = harness
            ._temp
            .path()
            .join(format!("takeover-authority-{receiver:03}"));
        let checkpoint =
            ready_rebase_checkpoint_bytes_v1(&root.join("checkpoint/checkpoint.sqlite3"));
        drop(harness.authorities.remove(receiver));
        let (core_config, application_config) = harness.recovery_configs.remove(receiver);
        assert_genuine_synced_context_pins_v1(&root, &core_config);
        let watermark_path = harness._temp.path().join(format!(
            "takeover-watermark-{receiver:03}/signer-watermark.v1"
        ));
        let recovered = trnm_poco_node::reopen_deployed_lab_ordinary_cut_v0(
            &root,
            core_config,
            application_config,
            |_| {
                LabFileWatermark::open(watermark_path).map_err(|_| {
                    trnm_consensus_signer_journal::ExternalWatermarkErrorV0::Unavailable
                })
            },
        )
        .unwrap();
        let facts = recovered.facts_v0();
        assert_eq!(
            facts.checkpoint_v0().encode_canonical().as_slice(),
            checkpoint
        );
        assert_eq!(facts.safety_revision_v0(), expected.safety_revision_v0());
        assert_eq!(facts.high_qc_v0(), expected.high_qc_v0());
        assert_eq!(facts.prepared_application_records_v0(), 3);
        assert_eq!(facts.proposal_validation_terminal_rows_v0(), 3);
        let native = rusqlite::Connection::open_with_flags(
            root.join("application/application.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: u64 = native
            .query_row(
                "SELECT COUNT(*) FROM native_durable_execution_p_v0 WHERE block_id=?1",
                [original.block().id().as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    });
}

#[test]
fn ready_synced_rebase_corrupt_selected_owners_refuse_before_checkpoint_cas_v1() {
    on_bounded_takeover_owner_stack_v0(|| {
        for mutation in ["selected-p", "selected-k", "checkpoint-namespace"] {
            let mut fixture = ready_synced_rebase_fixture_v1();
            let (harness, receiver, _) = &mut *fixture;
            let receiver = *receiver;
            let before = harness.authorities[receiver].facts_v0().unwrap();
            let root = harness
                ._temp
                .path()
                .join(format!("takeover-authority-{receiver:03}"));
            let checkpoint_path = root.join("checkpoint/checkpoint.sqlite3");
            let checkpoint = ready_rebase_checkpoint_bytes_v1(&checkpoint_path);
            let native_path = root.join("application/application.sqlite3");
            let selected = before.high_qc_v0().block_id();
            let observed_path = match mutation {
                "selected-p" => {
                    let connection = rusqlite::Connection::open(&native_path).unwrap();
                    assert_eq!(connection.execute("UPDATE native_durable_execution_p_v0 SET artifact_digest=zeroblob(32) WHERE block_id=?1", [selected.as_bytes().as_slice()]).unwrap(), 1);
                    checkpoint_path.clone()
                }
                "selected-k" => {
                    let native = rusqlite::Connection::open_with_flags(
                        &native_path,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                    )
                    .unwrap();
                    let artifact: Vec<u8> = native
                        .query_row(
                            "SELECT artifact FROM native_durable_execution_p_v0 WHERE block_id=?1",
                            [selected.as_bytes().as_slice()],
                            |r| r.get(0),
                        )
                        .unwrap();
                    drop(native);
                    let validation =
                        rusqlite::Connection::open(root.join("validation/validation.sqlite3"))
                            .unwrap();
                    assert_eq!(
                        validation
                            .execute(
                                "DELETE FROM proposal_validation_jobs_v0 WHERE artifact=?1",
                                [artifact]
                            )
                            .unwrap(),
                        1
                    );
                    checkpoint_path.clone()
                }
                "checkpoint-namespace" => {
                    let displaced = checkpoint_path.with_extension("displaced");
                    std::fs::rename(&checkpoint_path, &displaced).unwrap();
                    displaced
                }
                _ => unreachable!(),
            };
            let key_calls = Arc::new(AtomicUsize::new(0));
            harness.authorities[receiver].producer = ContinuousSignatureProducerV0(Box::new(
                ForbiddenSyncedSignatureProducerV1(Arc::clone(&key_calls)),
            ));
            harness.authorities[receiver].proposal_producer = ContinuousProposalSignatureProducerV0(
                Box::new(ForbiddenSyncedSignatureProducerV1(Arc::clone(&key_calls))),
            );
            let error = harness.authorities[receiver]
                .rebase_ready_parent_v1()
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("rebase Ready application parent"),
                "{mutation}: {error:#}"
            );
            assert!(harness.authorities[receiver].phase.is_none());
            assert_eq!(key_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                ready_rebase_checkpoint_bytes_v1(&observed_path),
                checkpoint,
                "{mutation} wrote checkpoint before authenticating source/path"
            );
        }
    });
}

// Comparisons use a strictly reopened real Safety head and real terminal K.
// Mutated contexts below are inert test inputs, never minted Safety authority.
fn assert_genuine_synced_context_pins_v1(root: &Path, core_config: &CoreConfig) {
    use trnm_consensus_safety_store::{
        NativeValidTransitionV0, SafetyStateStoreProfileV0, SafetyTransitionContextV0,
        SqliteSafetyStateStoreV0,
    };
    use trnm_native_application_sqlite::{
        ProposalValidationStoreScopeV0, SqliteProposalValidationStoreV0,
    };
    let profile = SafetyStateStoreProfileV0::new(
        core_config.clone(),
        trnm_poco_node::STRICT_ED25519_VERIFIER_PROFILE_REF_V0,
        trnm_consensus_core::SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .unwrap(),
        256 * 1024 * 1024,
    )
    .unwrap();
    let safety = SqliteSafetyStateStoreV0::open_existing(
        root.join("target-safety/safety.sqlite3"),
        profile,
        StrictEd25519Verifier,
    )
    .unwrap();
    let head = safety.confirmed_native_valid_head_v0().unwrap();
    let transition = head.transition();
    let path = root.join("validation/validation.sqlite3");
    let domain = b"trnm.poco-node.deployed-lab.proposal-scope.v0";
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    for part in [
        domain.as_slice(),
        core_config.validator_set().id().as_bytes(),
        core_config.local_validator().as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let scope: [u8; 32] = hasher.finalize().into();
    let mut validation = SqliteProposalValidationStoreV0::open(
        path,
        ProposalValidationStoreScopeV0::new(scope).unwrap(),
        0,
    )
    .unwrap();
    let audit = validation.confirm_terminal_k_audit_v0().unwrap();
    let binding = audit
        .terminal_bindings_v0()
        .iter()
        .find(|binding| {
            binding.block_id().as_bytes() == transition.validation_id().block_id().as_bytes()
                && binding.view() == transition.validation_id().view().get()
                && binding.generation() == transition.validation_id().generation()
        })
        .unwrap()
        .clone();
    assert_eq!(
        validation
            .confirm_synced_no_sign_native_valid_context_from_k_v1(
                &binding,
                head.transition_context(),
                head.state_record_checksum(),
            )
            .unwrap(),
        *head.transition_context()
    );
    let mut wrong_checksum = head.state_record_checksum();
    wrong_checksum[0] ^= 1;
    assert!(
        validation
            .confirm_synced_no_sign_native_valid_context_from_k_v1(
                &binding,
                head.transition_context(),
                wrong_checksum,
            )
            .is_err(),
        "terminal K must pin the exact original Safety record checksum"
    );
    let mut wrong_fingerprint = transition.request_fingerprint();
    wrong_fingerprint[0] ^= 1;
    let wrong_context = SafetyTransitionContextV0::native_valid(
        NativeValidTransitionV0::new(
            transition.route(),
            transition.validation_id(),
            wrong_fingerprint,
            transition.job_immutable_checksum(),
            transition.application_host_config_ref(),
            transition.valid_result_checksum(),
            transition.callback_payload_checksum(),
            transition.idempotency_key(),
            transition.delivery_attempt(),
            transition.delivered_job_row_checksum(),
            transition.outbox_checksum(),
            transition.post_ack_action_code(),
            transition.completion_revision(),
        )
        .unwrap(),
    );
    assert!(
        validation
            .confirm_synced_no_sign_native_valid_context_from_k_v1(
                &binding,
                &wrong_context,
                head.state_record_checksum(),
            )
            .is_err(),
        "immutable manifest must be derived from actual K, not copied from input context"
    );
    assert_eq!(
        validation
            .confirm_synced_no_sign_native_valid_context_from_k_v1(
                &binding,
                head.transition_context(),
                head.state_record_checksum(),
            )
            .unwrap(),
        *head.transition_context()
    );
}
