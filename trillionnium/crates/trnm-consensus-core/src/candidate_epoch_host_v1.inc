/// Default-off **trusted-host** epoch driver; this is not a durable receipt.
///
/// Core stays private. Before the exact initial StorageAck, this driver rejects
/// every other input and cannot issue an application capability. The operational
/// host must own and freshly join journal9, native C/edge, retired old custody,
/// virgin new custody and the independent full-epoch checkpoint before that ACK.
/// As with ordinary Core, a caller bypassing that host can lie about StorageAck;
/// this seam must never be presented as independently safe activation authority.
///
/// ```compile_fail
/// use trnm_consensus_core::PendingEpochHostDriverV1;
/// fn duplicate<T: Clone>() {}
/// duplicate::<PendingEpochHostDriverV1>();
/// ```
#[derive(Debug)]
pub struct PendingEpochHostDriverV1 {
    core: Box<Core>,
    initial_request: SafetyStatePersistenceV0,
    activation_pending: bool,
}

impl PreparedEpochCoreActivationV1 {
    /// Consumes the prepared owner without acknowledging any physical store.
    pub fn into_candidate_host_pending_v1(self) -> PendingEpochHostDriverV1 {
        PendingEpochHostDriverV1 {
            core: self.core,
            initial_request: self.initial_request,
            activation_pending: true,
        }
    }
}

impl StrictEpochCoreRecoveryV1 {
    /// Trusted-host reconstruction of the exact initial activation cut only.
    /// This creates a fresh process affinity and remints the same pending ACK,
    /// not a new Safety revision. Journal9 must freshly match and bind that
    /// request; all external owner reconciliation still precedes the host ACK.
    /// Any progressed state/outbox requires its dedicated recovery protocol.
    pub fn into_candidate_host_initial_pending_v1(self) -> Result<PendingEpochHostDriverV1> {
        let epoch = self
            .state
            .epoch_state_v1()
            .ok_or(CoreError::InvalidRecovery(
                "candidate epoch recovery lacks full context",
            ))?;
        let initial = SafetyState::from_epoch_activation_v1(
            &self.config,
            epoch.clone(),
            self.state.revision(),
        )?;
        if initial != *self.state {
            return Err(CoreError::InvalidRecovery(
                "candidate epoch initial recovery rejects progressed or pending-outbox state",
            ));
        }
        let barrier = BarrierId::new(self.state.revision());
        let mut core = Box::new(Core::empty(self.config, *self.state, false));
        core.pending_persistence = Some(PendingPersistence {
            barrier,
            deferred: vec![DeferredEffect::ArmViewTimer],
            safety_rules_shadow_transition: None,
            safety_rules_shadow_predecessor_digest: None,
        });
        let initial_request = SafetyStatePersistenceV0::new(
            barrier,
            Box::new(core.safety.clone()),
            None,
            None,
            None,
            Arc::clone(&core.persistence_affinity.0),
            CorePersistenceSealV0::new(),
        );
        core.validate_runtime(&trnm_consensus_crypto::StrictEd25519Verifier, true)?;
        Ok(PendingEpochHostDriverV1 {
            core,
            initial_request,
            activation_pending: true,
        })
    }
}

impl PendingEpochHostDriverV1 {
    pub fn config(&self) -> &CoreConfig {
        self.core.config()
    }
    pub fn state(&self) -> &SafetyState {
        self.core.safety_state()
    }
    pub fn initial_persistence_v1(&self) -> &SafetyStatePersistenceV0 {
        &self.initial_request
    }
    pub fn persistence_binding_v1(&self) -> SafetyStatePersistenceBindingV0 {
        self.core.safety_state_persistence_binding_v0()
    }
    pub const fn activation_persistence_pending_v1(&self) -> bool {
        self.activation_pending
    }
    fn require_activated_v1(&self) -> Result<()> {
        if self.activation_pending {
            Err(CoreError::EpochActivationPersistencePending)
        } else {
            Ok(())
        }
    }
    pub fn step_v1(&mut self, input: Input) -> Result<Vec<Effect>> {
        if self.activation_pending {
            match &input {
                Input::StorageAck { barrier } if *barrier == self.initial_request.barrier() => {}
                Input::StorageAck { .. } => return Err(CoreError::UnexpectedStorageAck),
                _ => return Err(CoreError::EpochActivationPersistencePending),
            }
        }
        let effects = self
            .core
            .step(input, &trnm_consensus_crypto::StrictEd25519Verifier)?;
        // A failed ACK leaves the pending gate and private Core unchanged.
        self.activation_pending = false;
        Ok(effects)
    }
    pub fn issue_application_seal_authority_v1(
        &self,
    ) -> Result<CoreIssuedApplicationSealAuthorityV0> {
        self.require_activated_v1()?;
        self.core.issue_application_seal_authority_v0()
    }
    pub fn issue_application_finalization_apply_authority_v1(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationApplyAuthorityV0> {
        self.require_activated_v1()?;
        self.core
            .issue_application_finalization_apply_authority_v0()
    }
    pub fn issue_application_finalization_permit_v1(
        &self,
    ) -> Result<CoreIssuedApplicationFinalizationPermitV0> {
        self.require_activated_v1()?;
        self.core.issue_application_finalization_permit_v0()
    }
    pub fn step_application_sealed_valid_v1(
        &mut self,
        proof: &ApplicationSealedValidV0,
    ) -> Result<Vec<Effect>> {
        self.require_activated_v1()?;
        self.core
            .step_application_sealed_valid_v0(proof, &trnm_consensus_crypto::StrictEd25519Verifier)
    }
    pub fn step_application_finalization_receipt_v1(
        &mut self,
        receipt: ApplicationFinalizationReceiptV0,
    ) -> core::result::Result<Vec<Effect>, ApplicationFinalizationReceiptRejectionV0> {
        if let Err(error) = self.require_activated_v1() {
            return Err(ApplicationFinalizationReceiptRejectionV0::new(
                error,
                Box::new(receipt),
            ));
        }
        self.core.step_application_finalization_receipt_v0(
            receipt,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
    pub fn persist_signature_release_v1(
        &mut self,
        released_from: &SafetyState,
    ) -> Result<Vec<Effect>> {
        self.require_activated_v1()?;
        self.core.persist_signature_release_v0(
            released_from,
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
    }
}

#[cfg(test)]
mod candidate_epoch_host_tests_v1 {
    use super::*;
    use crate::epoch_state_tests_v1 as fixture;

    // Pure Core fixture: strict Ed25519 evidence is real; application artifact
    // identifiers below are synthetic and do not claim a native-store join.
    fn pending() -> PendingEpochHostDriverV1 {
        let runtime = fixture::runtime();
        let config = fixture::config(&runtime);
        let limits = crate::minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
        let artifact = fixture::artifact(&runtime);
        let context =
            crate::EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits)
                .unwrap();
        let state =
            SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 43).unwrap();
        let raw = crate::encode_epoch_safety_record_v1(&state, &context).unwrap();
        let record = crate::decode_epoch_safety_record_v1_exact(&raw, &context).unwrap();
        Core::prepare_epoch_recovery_v1(&record, &context, record.record_checksum())
            .unwrap()
            .into_candidate_host_initial_pending_v1()
            .unwrap()
    }

    fn persistence(effects: Vec<Effect>) -> SafetyStatePersistenceV0 {
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            panic!("expected exact persistence, got {effects:?}");
        };
        request.clone()
    }

    #[test]
    fn initial_gate_releases_one_timer_only_after_exact_ack() {
        let mut driver = pending();
        let before = driver.state().clone();
        let barrier = driver.initial_persistence_v1().barrier();
        assert!(driver
            .persistence_binding_v1()
            .accepts(driver.initial_persistence_v1()));
        assert_eq!(
            driver.step_v1(Input::Resume),
            Err(CoreError::EpochActivationPersistencePending)
        );
        assert_eq!(
            driver.step_v1(Input::LocalTimeout {
                epoch: before.epoch(),
                view: before.current_view()
            }),
            Err(CoreError::EpochActivationPersistencePending)
        );
        assert_eq!(
            driver.step_v1(Input::StorageAck {
                barrier: BarrierId::new(barrier.get() + 1)
            }),
            Err(CoreError::UnexpectedStorageAck)
        );
        assert!(matches!(
            driver.issue_application_seal_authority_v1(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert!(matches!(
            driver.issue_application_finalization_apply_authority_v1(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert!(matches!(
            driver.issue_application_finalization_permit_v1(),
            Err(CoreError::EpochActivationPersistencePending)
        ));
        assert_eq!(driver.state(), &before);
        assert!(driver.activation_persistence_pending_v1());
        assert_eq!(
            driver.step_v1(Input::StorageAck { barrier }).unwrap(),
            vec![Effect::ArmViewTimer {
                epoch: before.epoch(),
                view: View::new(1)
            }]
        );
        assert!(!driver.activation_persistence_pending_v1());
        assert_eq!(driver.state(), &before);
        assert_eq!(
            driver.step_v1(Input::StorageAck { barrier }),
            Err(CoreError::UnexpectedStorageAck)
        );
        let request = persistence(
            driver
                .step_v1(Input::LocalTimeout {
                    epoch: before.epoch(),
                    view: View::new(1),
                })
                .unwrap(),
        );
        assert!(request.state().pending_sign().is_some());
        assert!(matches!(
            driver
                .step_v1(Input::StorageAck {
                    barrier: request.barrier()
                })
                .unwrap()
                .as_slice(),
            [Effect::RequestSignature { .. }]
        ));
    }

    #[test]
    fn strict_first_proposal_crosses_real_obligation_and_valid_barriers() {
        run_first_proposal(1);
    }

    #[test]
    fn strict_tc_before_first_proposal_uses_same_public_obligation_path() {
        run_first_proposal(3);
    }

    fn run_first_proposal(first_view: u64) {
        let mut driver = pending();
        let runtime = fixture::runtime();
        let (proposal, _, commitments) = fixture::first_chain(&runtime, &[first_view]).remove(0);
        assert_eq!(
            driver.step_v1(Input::Proposal(Box::new(proposal.clone()))),
            Err(CoreError::EpochActivationPersistencePending)
        );
        driver
            .step_v1(Input::StorageAck {
                barrier: driver.initial_persistence_v1().barrier(),
            })
            .unwrap();
        let seal = driver.issue_application_seal_authority_v1().unwrap();
        let before_proposal = driver.state().clone();
        let request = persistence(
            driver
                .step_v1(Input::Proposal(Box::new(proposal.clone())))
                .unwrap(),
        );
        assert!(request.state().pending_sign().is_none());
        assert_eq!(request.state().payload_validation_obligations().len(), 1);
        Core::validate_persisted_successor_v0(
            driver.config(),
            &before_proposal,
            request.state(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .unwrap();
        // A genuine progressed obligation cannot be mistaken for initial
        // activation recovery, even though its complete 14E record is valid.
        {
            let limits =
                crate::minimum_epoch_safety_record_limits_v1(driver.config(), &runtime).unwrap();
            let context = crate::EpochSafetyStateRecordContextV1::new(
                driver.config(),
                fixture::runtime(),
                fixture::artifact(&runtime),
                2,
                limits,
            )
            .unwrap();
            let raw = crate::encode_epoch_safety_record_v1(request.state(), &context).unwrap();
            let record = crate::decode_epoch_safety_record_v1_exact(&raw, &context).unwrap();
            let recovery =
                Core::prepare_epoch_recovery_v1(&record, &context, record.record_checksum())
                    .unwrap();
            assert!(recovery.into_candidate_host_initial_pending_v1().is_err());
        }
        let released = driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .unwrap();
        assert!(released
            .iter()
            .all(|e| matches!(e, Effect::ValidatePayload(_) | Effect::ArmViewTimer { .. })));
        let mut validations = released.into_iter().filter_map(|e| match e {
            Effect::ValidatePayload(v) => Some(v),
            _ => None,
        });
        let validation = validations
            .next()
            .expect("missing validation after persistence");
        assert!(validations.next().is_none());
        let (_, id, block, parent, permit) = validation.try_claim().unwrap().into_parts();
        assert_eq!(block.id(), proposal.block().id());
        assert_eq!(
            parent.tip().height(),
            runtime
                .activation()
                .old_checkpoint_finality()
                .finalized_block()
                .header()
                .height()
        );
        assert_eq!(
            parent.consensus_parent_tip_v1().block_id(),
            runtime.activation().terminal_old_header().id()
        );
        let wrong = PayloadValidationResult::authorized_valid_v0(
            commitments,
            crate::ValidatedPayloadArtifactRefV0::new(
                crate::BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), [0x31; 32]),
                [0x32; 32],
            ),
        );
        assert!(driver
            .step_v1(Input::PayloadValidated { id, result: wrong })
            .is_err());
        assert!(driver.state().pending_sign().is_none());
        let artifact = crate::ValidatedPayloadArtifactRefV0::new(
            crate::BlockIdOverlayRefV0::for_epoch_application_v1(
                block.id(),
                parent.tip().block_id(),
                parent.consensus_parent_tip_v1().block_id(),
                driver
                    .state()
                    .epoch_state_v1()
                    .unwrap()
                    .activation_binding(),
                [0x31; 32],
            )
            .unwrap(),
            [0x32; 32],
        );
        let proof = seal.seal_after_application_store_commit_v0(permit, commitments, artifact);
        let before_valid = driver.state().clone();
        let request = persistence(driver.step_application_sealed_valid_v1(&proof).unwrap());
        assert!(request.native_valid_post_ack_action_v0().is_some());
        assert!(request.state().payload_validation_obligations().is_empty());
        Core::validate_persisted_successor_v0(
            driver.config(),
            &before_valid,
            request.state(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .unwrap();
        assert!(matches!(
            driver
                .step_v1(Input::StorageAck {
                    barrier: request.barrier()
                })
                .unwrap()
                .as_slice(),
            [Effect::RequestSignature { .. }]
        ));
    }
}
