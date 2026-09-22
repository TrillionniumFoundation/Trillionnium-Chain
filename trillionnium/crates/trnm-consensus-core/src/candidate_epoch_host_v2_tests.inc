// Pure Core tests: real signed activation evidence, explicitly fixture-only
// application coordinates. No native journal/custody durability is claimed.
#[cfg(feature = "candidate-epoch-host-v2")]
mod candidate_host_v2 {
    use super::*;

    #[inline(never)]
    fn initial_recovery(
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> StrictEpochCoreRecoveryV2 {
        let state = Box::new(
            SafetyState::from_epoch_activation_v1(
                context.core_config(),
                context.epoch().clone(),
                SOURCE_REVISION,
            )
            .unwrap(),
        );
        recover_source(&state, context)
    }

    #[inline(never)]
    fn activated(context: &EpochSafetyStateRecordContextV2<'_>) -> PendingEpochHostDriverV2 {
        let mut driver = initial_recovery(context)
            .into_candidate_host_initial_pending_v2()
            .unwrap();
        let barrier = driver.initial_persistence_v2().barrier();
        assert!(matches!(
            driver
                .step_v2(Input::StorageAck { barrier })
                .unwrap()
                .as_slice(),
            [Effect::ArmViewTimer { .. }]
        ));
        driver
    }

    #[test]
    fn codec2_candidate_initial_gate_and_recovery_affinity_are_exact() {
        let f = TransitionFixture::new();
        let context = f.source_context();
        let mut driver = initial_recovery(&context)
            .into_candidate_host_initial_pending_v2()
            .unwrap();
        let second = initial_recovery(&context)
            .into_candidate_host_initial_pending_v2()
            .unwrap();
        let before = Box::new(driver.state().clone());
        let barrier = driver.initial_persistence_v2().barrier();
        assert!(driver
            .persistence_binding_v2()
            .accepts(driver.initial_persistence_v2()));
        assert!(!driver
            .persistence_binding_v2()
            .accepts(second.initial_persistence_v2()));
        assert_eq!(
            driver.step_v2(Input::Resume),
            Err(CoreError::EpochActivationPersistencePending)
        );
        assert_eq!(
            driver.step_v2(Input::LocalTimeout {
                epoch: before.epoch(),
                view: before.current_view()
            }),
            Err(CoreError::EpochActivationPersistencePending)
        );
        assert_eq!(
            driver.step_v2(Input::StorageAck {
                barrier: BarrierId::new(barrier.get() + 1)
            }),
            Err(CoreError::UnexpectedStorageAck)
        );
        assert!(matches!(
            driver.issue_application_seal_authority_v2(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert!(matches!(
            driver.issue_application_finalization_apply_authority_v2(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert!(matches!(
            driver.issue_application_finalization_permit_v2(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert_eq!(driver.state(), before.as_ref());
        assert!(driver.activation_persistence_pending_v2());
        assert_eq!(
            driver.step_v2(Input::StorageAck { barrier }).unwrap(),
            vec![Effect::ArmViewTimer {
                epoch: before.epoch(),
                view: View::new(1)
            }]
        );
        assert_eq!(driver.state(), before.as_ref());
        assert!(!driver.activation_persistence_pending_v2());
        assert_eq!(
            driver.step_v2(Input::StorageAck { barrier }),
            Err(CoreError::UnexpectedStorageAck)
        );
        assert!(driver.issue_application_seal_authority_v2().is_ok());
    }

    #[inline(never)]
    fn reject_live_cut(f: &TransitionFixture, cut: u8) {
        let context = f.source_context();
        let target = f.target_context(SOURCE_GENERATION + 1, 0x71);
        let mut driver = initial_recovery(&context)
            .into_candidate_host_initial_pending_v2()
            .unwrap();
        if cut > 0 {
            let barrier = driver.initial_persistence_v2().barrier();
            driver.step_v2(Input::StorageAck { barrier }).unwrap();
        }
        if cut >= 2 {
            let effects = driver
                .step_v2(Input::LocalTimeout {
                    epoch: driver.state().epoch(),
                    view: driver.state().current_view(),
                })
                .unwrap();
            let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
                panic!("one timeout persistence required");
            };
            assert!(driver.persistence_binding_v2().accepts(request));
            assert!(request.state().pending_sign().is_some());
            let recovery = recover_source(request.state(), &context);
            assert!(recovery.into_candidate_host_initial_pending_v2().is_err());
            if cut == 3 {
                assert!(matches!(
                    driver
                        .step_v2(Input::StorageAck {
                            barrier: request.barrier()
                        })
                        .unwrap()
                        .as_slice(),
                    [Effect::RequestSignature { .. }]
                ));
            }
        }
        let error = driver.prepare_next_epoch_v2(&target).unwrap_err();
        match cut {
            0 => assert_eq!(error, CoreError::EpochActivationPersistencePending),
            1 => assert!(matches!(error, CoreError::InvalidRecovery(UNRESOLVED))),
            _ => assert!(matches!(
                error,
                CoreError::InvalidRecovery("epoch activation has a pending live owner cut")
            )),
        }
    }

    #[test]
    fn codec2_candidate_consuming_successor_rejects_unacked_unsettled_and_pending_signatures() {
        let f = TransitionFixture::new();
        for cut in 0..4 {
            reject_live_cut(&f, cut);
        }
    }

    #[test]
    fn codec2_candidate_real_proposal_waits_for_validation_ack_and_typed_valid() {
        let f = TransitionFixture::new();
        let context = f.source_context();
        let mut driver = activated(&context);
        let (proposal, _, commitments) =
            epoch_state_tests_v1::first_chain(context.runtime(), &[1]).remove(0);
        let seal = driver.issue_application_seal_authority_v2().unwrap();
        let effects = driver
            .step_v2(Input::Proposal(Box::new(proposal.clone())))
            .unwrap();
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            panic!("proposal barrier");
        };
        assert_eq!(request.state().payload_validation_obligations().len(), 1);
        assert!(request.state().pending_sign().is_none());
        assert!(driver.persistence_binding_v2().accepts(request));
        let recovery = recover_source(request.state(), &context);
        assert!(recovery.into_candidate_host_initial_pending_v2().is_err());
        let effects = driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier(),
            })
            .unwrap();
        let mut validations = effects.into_iter().filter_map(|e| match e {
            Effect::ValidatePayload(v) => Some(v),
            Effect::ArmViewTimer { .. } => None,
            other => panic!("unexpected effect {other:?}"),
        });
        let validation = validations.next().unwrap();
        assert!(validations.next().is_none());
        let (_, _, block, parent, permit) = validation.try_claim().unwrap().into_parts();
        assert_eq!(block.id(), proposal.block().id());
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::for_epoch_application_v1(
                block.id(),
                parent.tip().block_id(),
                parent.consensus_parent_tip_v1().block_id(),
                context.epoch().activation_binding(),
                [0x31; 32],
            )
            .unwrap(),
            [0x32; 32],
        );
        let proof = seal.seal_after_application_store_commit_v0(permit, commitments, artifact);
        let effects = driver.step_application_sealed_valid_v2(&proof).unwrap();
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            panic!("native Valid barrier");
        };
        assert!(request.native_valid_post_ack_action_v0().is_some());
        assert!(request.state().payload_validation_obligations().is_empty());
        assert!(driver.persistence_binding_v2().accepts(request));
        assert!(matches!(
            driver
                .step_v2(Input::StorageAck {
                    barrier: request.barrier()
                })
                .unwrap()
                .as_slice(),
            [Effect::RequestSignature { .. }]
        ));
        assert!(driver
            .prepare_next_epoch_v2(&f.target_context(SOURCE_GENERATION + 1, 0x71))
            .is_err());
    }

    // This is an independently validated pure-Core settled-state fixture, not
    // a claim that a native host or journal drove the intermediate history.
    #[inline(never)]
    fn settled_core(
        f: &TransitionFixture,
        epoch: crate::EpochCoreStateV1,
        target: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Box<Core> {
        Box::new(Core::empty(
            f.old_config.clone(),
            settled_source(&f.old_config, epoch, target),
            false,
        ))
    }

    #[test]
    fn codec2_candidate_consuming_transition_preserves_preparation_affinity_and_applied_cut() {
        let f = TransitionFixture::new();
        let context = f.source_context();
        let target = f.target_context(SOURCE_GENERATION + 1, 0x71);
        let mut source = activated(&context);
        source.core = settled_core(&f, context.epoch().clone(), &target);
        let previous = Box::new(source.state().clone());
        let prepared = source.prepare_next_epoch_v2(&target).unwrap();
        assert_eq!(prepared.predecessor(), previous.as_ref());
        let binding = prepared.persistence_binding_v2();
        let mut target_driver = prepared.into_candidate_host_pending_v2();
        assert!(binding.accepts(target_driver.initial_persistence_v2()));
        assert_eq!(target_driver.state().revision(), previous.revision() + 1);
        assert_eq!(
            target_driver.state().application_applied(),
            previous.application_applied()
        );
        assert_eq!(
            target_driver.step_v2(Input::Resume),
            Err(CoreError::EpochActivationPersistencePending)
        );

        let mut behind = activated(&context);
        behind.core = settled_core(&f, context.epoch().clone(), &target);
        let durable = behind.state().last_finalization().unwrap().clone();
        behind
            .core
            .safety
            .set_application_applied(durable.authenticated_parent());
        behind
            .core
            .safety
            .set_finalization_queue(vec![durable.clone()]);
        behind
            .core
            .safety
            .set_pending_finalize(Some(durable.proof_id()));
        assert!(behind.prepare_next_epoch_v2(&target).is_err());
    }

    #[cfg(feature = "candidate-epoch-host-v1")]
    #[test]
    fn codec1_candidate_consuming_transition_requires_exact_v2_extension() {
        let f = TransitionFixture::new();
        let runtime =
            StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap();
        let limits = minimum_epoch_safety_record_limits_v1(&f.old_config, &runtime).unwrap();
        let context = EpochSafetyStateRecordContextV1::new(
            &f.old_config,
            runtime,
            f.initial_artifact,
            SOURCE_GENERATION,
            limits,
        )
        .unwrap();
        let initial = Box::new(
            SafetyState::from_epoch_activation_v1(
                &f.old_config,
                context.epoch().clone(),
                SOURCE_REVISION,
            )
            .unwrap(),
        );
        let raw = encode_epoch_safety_record_v1(&initial, &context).unwrap();
        let record = decode_epoch_safety_record_v1_exact(&raw, &context).unwrap();
        let recovery =
            Core::prepare_epoch_recovery_v1(&record, &context, record.record_checksum()).unwrap();
        let mut source = recovery.into_candidate_host_initial_pending_v1().unwrap();
        let barrier = source.initial_persistence_v1().barrier();
        source.step_v1(Input::StorageAck { barrier }).unwrap();
        let target = f.target_context(SOURCE_GENERATION + 1, 0x71);
        source.core = settled_core(&f, context.epoch().clone(), &target);
        let prepared = source.prepare_next_epoch_v2(&target).unwrap();
        assert_eq!(prepared.state().epoch_state_v1(), Some(target.epoch()));
        assert!(prepared
            .persistence_binding_v2()
            .accepts(prepared.initial_persistence_v2()));
    }
}
