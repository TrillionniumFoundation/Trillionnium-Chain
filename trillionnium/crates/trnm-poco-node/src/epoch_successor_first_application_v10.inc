// Real first-application continuation for the Journal12/V2 successor.
// This owner consumes the actual later successor edge and never exposes Core,
// signer or native write capabilities. A later checkpoint/handoff remains a
// separate transition; no second epoch is fabricated by this slice.
#[must_use]
pub struct SuccessorFirstApplicationRuntimeV10<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
    O: ExternalMonotonicWatermarkV0,
> {
    runtime: Box<SuccessorEpochRuntimeV9<W, N, H, O>>,
    seal_authority: CoreIssuedApplicationSealAuthorityV0,
    pending_validation: Option<PayloadValidationRequest>,
    pending_epoch_commit: Option<PendingEpochCommitV1>,
}

fn application_head_from_cut_v10(cut: EpochApplicationCutV1) -> Result<trnm_native_application::ApplicationHeadV0> {
    Ok(trnm_native_application::ApplicationHeadV0::new(
        trnm_native_application::HeightV0::new(cut.height),
        trnm_native_application::BlockIdV0::new(cut.block_id)?,
        trnm_native_application::StateRootV0::new(cut.state_root)?,
        trnm_native_application::ApplicationCommitIdV0::new(cut.native_commit_id)?,
    ))
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
        O: ExternalMonotonicWatermarkV0,
    > SuccessorEpochRuntimeV9<W, N, H, O>
{
    pub fn begin_first_application_v10(
        mut self,
    ) -> Result<SuccessorFirstApplicationRuntimeV10<W, N, H, O>> {
        self.confirm_activated_cut_v9()?;
        ensure!(
            self.startup.is_empty(),
            "successor startup timer must be consumed before application admission"
        );
        let seal_authority = self
            .driver
            .issue_application_seal_authority_v2()
            .map_err(|e| anyhow::anyhow!("successor seal authority: {e:?}"))?;
        Ok(SuccessorFirstApplicationRuntimeV10 {
            runtime: Box::new(self),
            seal_authority,
            pending_validation: None,
            pending_epoch_commit: None,
        })
    }
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
        O: ExternalMonotonicWatermarkV0,
    > SuccessorFirstApplicationRuntimeV10<W, N, H, O>
{
    fn application(&self) -> &DurableNativeApplicationV0 {
        &self.runtime.source.roles.retired.source.application
    }

    fn edge(&self) -> &trnm_native_execution_v0::LaterEpochApplicationEdgeV1 {
        &self.runtime.source.edge
    }

    fn ordinary_cut_v10(&mut self) -> Result<EpochOrdinaryCustodyCutV1> {
        let head = self.runtime.ordinary.confirm_node_checkpoint_head_exact_v0()?;
        let mark = head.exact_watermark();
        let expected = self
            .runtime
            .checkpoint
            .fields()
            .ordinary
            .context("successor checkpoint lacks ordinary custody")?;
        ensure!(
            head.belongs_to_operational_journal_at_path_v0(
                &self.runtime.ordinary,
                self.runtime.ordinary.path(),
            ) && mark.scope() == expected.scope
                && mark.journal_id() == expected.journal_id
                && head.profile_checksum() == expected.profile_checksum
                && self.runtime.ordinary.profile().validator_set()
                    == self.runtime.driver.config().validator_set()
                && self.runtime.ordinary.profile().author()
                    == self.runtime.driver.config().local_validator()
                && head.pending_intent().is_none(),
            "successor ordinary custody changed"
        );
        Ok(EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: head.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        })
    }

    fn confirm_active_cut_v10(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.runtime.fenced, "successor application owner fenced");
        let result = (|| {
            self.runtime
                .source
                .roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.runtime.checkpoint)?;
            ensure!(
                matches!(
                    self.runtime.checkpoint.fields().phase,
                    EpochCheckpointPhaseV1::SuccessorActivationNative13Journal12
                        | EpochCheckpointPhaseV1::Ordinary
                ),
                "successor application checkpoint phase"
            );
            let fresh = self.runtime.journal.fresh_read_v4(self.runtime.pin)?;
            ensure!(
                fresh.belongs_to_store_at_path_v4(
                    &self.runtime.journal,
                    self.runtime.journal.path_v4(),
                ) && fresh.state_v4() == self.runtime.driver.state()
                    && safety_cut_v9(&fresh) == self.runtime.checkpoint.fields().target_safety,
                "successor Safety owner changed"
            );
            let _ = self.ordinary_cut_v10()?;
            let edge = self.edge();
            let app = self.runtime.checkpoint.fields().application;
            ensure!(
                edge.belongs_to_application(self.application())
                    && edge.successor_binding()
                        == self.runtime.checkpoint.fields().edge.native_authorization_id
                    && self.runtime.driver.config().validator_set().id().as_bytes()
                        == &self.runtime.checkpoint.fields().validator_set_id
                    && self
                        .runtime
                        .driver
                        .config()
                        .consensus_parameters()
                        .hash()
                        .as_bytes()
                        == &self.runtime.checkpoint.fields().parameters_hash,
                "successor application authority changed"
            );
            let head = self.application().confirmed_committed_head_v0()?;
            ensure!(
                head.height().get() == app.height
                    && head.block_id().as_bytes() == &app.block_id
                    && head.state_root().as_bytes() == &app.state_root
                    && head.commit_id().as_bytes() == &app.native_commit_id
                    && self.application().config_v0().store_id() == app.native_store_id,
                "successor native head differs from independent checkpoint"
            );
            if app.height == edge.checkpoint_height() {
                ensure!(
                    app.block_id == edge.checkpoint_block()
                        && app.state_root == edge.checkpoint_root()
                        && app.native_commit_id == edge.checkpoint_commit_id(),
                    "successor activation parent differs"
                );
            } else {
                let confirmed = self
                    .application()
                    .confirm_current_epoch_execution_v1(app.block_id)?;
                let header = confirmed.prepared().header()?;
                ensure!(
                    confirmed.commit_sequence() == Some(app.commit_sequence)
                        && confirmed.prepared().persist_sequence() == app.p_sequence
                        && confirmed.prepared().p_digest() == app.p_digest
                        && confirmed.prepared().artifact_digest() == app.artifact_digest
                        && confirmed.overlay_checksum() == app.overlay_digest
                        && header.epoch() == self.runtime.driver.config().validator_set().epoch()
                        && header.validator_set_id()
                            == self.runtime.driver.config().validator_set().id()
                        && header.consensus_parameters_hash()
                            == self.runtime.driver.config().consensus_parameters().hash(),
                    "successor progressed native row differs"
                );
            }
            self.runtime
                .source
                .roles
                .retired
                .checkpoint_store
                .confirm_exact(&self.runtime.checkpoint)?;
            Ok(self.runtime.checkpoint)
        })();
        if result.is_err() {
            self.runtime.fenced = true;
        }
        result
    }

    fn advance_checkpoint_v10(
        &mut self,
        safety: EpochSafetyCutV1,
        ordinary: EpochOrdinaryCustodyCutV1,
        application: EpochApplicationCutV1,
    ) -> Result<()> {
        let old = self.runtime.checkpoint;
        self.runtime
            .source
            .roles
            .retired
            .checkpoint_store
            .confirm_exact(&old)?;
        let mut fields = *old.fields();
        fields.phase = EpochCheckpointPhaseV1::Ordinary;
        fields.generation = fields
            .generation
            .checked_add(1)
            .context("successor checkpoint generation exhausted")?;
        fields.predecessor_checksum = old.checksum();
        fields.target_safety = safety;
        fields.ordinary = Some(ordinary);
        fields.application = application;
        let next = EpochNodeCheckpointV1::new(fields)?;
        next.validate_successor_of(&old)?;
        self.runtime
            .source
            .roles
            .retired
            .checkpoint_store
            .compare_and_advance(&old, &next)?;
        self.runtime.checkpoint = next;
        self.confirm_active_cut_v10()?;
        Ok(())
    }

    pub fn admit_first_proposal_v10(mut self, proposal: SignedProposalV0) -> Result<Self> {
        self.confirm_active_cut_v10()?;
        ensure!(
            self.pending_validation.is_none() && self.pending_epoch_commit.is_none(),
            "successor proposal already pending"
        );
        let app = self.runtime.checkpoint.fields().application;
        let edge = self.edge();
        ensure!(
            app.height == edge.checkpoint_height()
                && app.block_id == edge.checkpoint_block()
                && proposal.block().header().epoch() == self.runtime.driver.state().epoch()
                && proposal.block().header().block_kind() == BlockKind::EpochHandoff
                && proposal.block().header().height().get() == edge.first_application_height()
                && self.runtime.driver.state().pending_sign().is_none()
                && self.runtime.driver.state().pending_finalize().is_none()
                && self.runtime.driver.state().payload_validation_obligations().is_empty(),
            "successor first proposal admission phase"
        );
        let effects = self
            .runtime
            .driver
            .step_v2(Input::Proposal(Box::new(proposal)))
            .map_err(|e| anyhow::anyhow!("successor proposal admission: {e:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("successor proposal did not yield one Safety persistence barrier")
        };
        let head = self.runtime.journal.persist_exact_v4(
            self.runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.runtime.pin = head.pin_v4();
        let ordinary = self.ordinary_cut_v10()?;
        self.advance_checkpoint_v10(safety_cut_v9(&head), ordinary, app)?;
        self.runtime.journal.confirm_exact_request_v4(
            self.runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let released = self
            .runtime
            .driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("successor proposal ACK: {e:?}"))?;
        let mut validation = None;
        for effect in released {
            match effect {
                Effect::ValidatePayload(candidate) if validation.is_none() => {
                    validation = Some(candidate)
                }
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("successor proposal ACK yielded unexpected effect"),
            }
        }
        self.pending_validation = Some(
            validation.context("successor proposal yielded no validation request")?,
        );
        self.confirm_active_cut_v10()?;
        Ok(self)
    }

    #[inline(never)]
    fn compute_first_valid_v10(&mut self) -> Result<Box<PreparedEpochValidDeliveryV2>> {
        let request = self
            .pending_validation
            .take()
            .context("successor validation is not pending")?;
        let claimed = request
            .try_claim()
            .map_err(|_| anyhow::anyhow!("successor validation was already claimed"))?;
        let (route, validation_id, block, parent, permit) = claimed.into_parts();
        ensure!(
            route == trnm_consensus_core::PayloadValidationRouteV0::Proposal,
            "successor execution route"
        );
        let edge = self.edge();
        ensure!(
            block.header().block_kind() == BlockKind::EpochHandoff
                && block.header().height().get() == edge.first_application_height()
                && parent.consensus_parent_tip_v1().block_id().as_bytes()
                    == &edge.terminal_block(),
            "successor first block/consensus parent"
        );
        let app_parent = application_head_from_cut_v10(self.runtime.checkpoint.fields().application)?;
        ensure!(
            parent.tip().block_id().as_bytes() == app_parent.block_id().as_bytes()
                && parent.tip().height().get() == app_parent.height().get(),
            "successor application parent witness"
        );
        let set = self.runtime.driver.config().validator_set();
        let params = self.runtime.driver.config().consensus_parameters();
        let payload = decode_application_payload_v0_exact(block.application_payload(), params)
            .map_err(|e| anyhow::anyhow!("successor payload decode: {e:?}"))?;
        let preview_request = trnm_native_application::NativeEpochBlockPreviewRequestV1::new(
            trnm_native_application::ChainIdV0::new(set.chain_id().as_str())?,
            trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes())?,
            app_parent,
            trnm_native_application::BlockIdV0::new(edge.terminal_block())?,
            trnm_native_application::HeightV0::new(edge.terminal_height()),
            trnm_native_application::Hash32V0::new(edge.successor_binding()),
            trnm_native_application::HeightV0::new(edge.first_application_height()),
            block.header().timestamp_ms(),
            trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes())?,
            payload.transactions().to_vec(),
        )?;
        let preview = self
            .application()
            .preview_later_epoch_block_v1(edge, &preview_request)?;
        ensure!(
            block.header().payload_root().as_bytes() == preview.payload_root().as_bytes()
                && block.header().state_root().as_bytes()
                    == preview.post_state_root().as_bytes()
                && block.header().receipts_root().as_bytes()
                    == preview.receipts_root().as_bytes()
                && block.header().evidence_root().as_bytes()
                    == preview.evidence_root().as_bytes(),
            "successor proposal roots differ from native preview"
        );
        let execution = trnm_native_application::NativeEpochBlockExecutionRequestV1::new(
            preview_request,
            trnm_native_application::BlockIdV0::new(*block.id().as_bytes())?,
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                trnm_native_application::Hash32V0::new(*preview.payload_root().as_bytes()),
                trnm_native_application::StateRootV0::new(*preview.post_state_root().as_bytes())?,
                trnm_native_application::ReceiptsRootV0::new(*preview.receipts_root().as_bytes())?,
                trnm_native_application::Hash32V0::new(*preview.evidence_root().as_bytes()),
            )?,
        )?;
        let prepared = self.application().prepare_later_epoch_first_new_block_v1(
            edge,
            execution,
            block.header(),
        )?;
        let confirmed = self
            .application()
            .confirm_prepared_epoch_execution_v1(&prepared)?;
        ensure!(
            confirmed.prepared().header()? == *block.header(),
            "successor P header substitution"
        );
        let (stored_payload, receipts) = confirmed.application_payload_and_receipts()?;
        ensure!(stored_payload == payload, "successor P payload substitution");
        let evidence = block
            .evidence_objects()
            .iter()
            .map(|encoded| {
                decode_double_vote_evidence_v0_exact(encoded, set)
                    .map_err(|e| anyhow::anyhow!("successor evidence decode: {e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let body = BlockBodyV0::new(payload, evidence)
            .map_err(|e| anyhow::anyhow!("successor body: {e:?}"))?;
        let commitments = body
            .validate_epoch_handoff_commitments_v1(
                block.header(),
                &receipts,
                params,
                block.header().state_root(),
                set,
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("successor commitments: {e:?}"))?;
        let activation = self
            .runtime
            .driver
            .state()
            .epoch_state_v1()
            .context("successor epoch state missing")?
            .activation_binding();
        let artifact = trnm_consensus_core::ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::for_epoch_application_v1(
                block.id(),
                BlockId::new(self.runtime.checkpoint.fields().application.block_id),
                BlockId::new(edge.terminal_block()),
                activation,
                confirmed.overlay_checksum(),
            )
            .map_err(|e| anyhow::anyhow!("successor artifact binding: {e:?}"))?,
            confirmed.artifact_checksum(),
        );
        let sealed = self
            .seal_authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact);
        let accepted = self
            .runtime
            .driver
            .step_application_sealed_valid_to_delivery_v2(&sealed)
            .map_err(|e| anyhow::anyhow!("successor Core D: {e:?}"))?;
        Ok(Box::new(PreparedEpochValidDeliveryV2 {
            prepared,
            confirmed,
            accepted: Box::new(accepted),
            route,
            validation_id,
        }))
    }

    fn persist_valid_v10(
        &mut self,
        accepted: &trnm_consensus_core::CoreAcceptedApplicationValidDV0,
        confirmed: &trnm_native_execution_v0::ConfirmedPreparedNativeEpochExecutionV1,
        route: trnm_consensus_core::PayloadValidationRouteV0,
        validation_id: trnm_consensus_core::ValidationId,
    ) -> Result<Vec<Effect>> {
        let persistence = accepted.persistence_request_v0();
        let p = confirmed.prepared();
        let edge_binding = self.edge().successor_binding();
        let store_id = self.application().config_v0().store_id();
        let request_fingerprint = epoch_transition_digest(
            "request-v10",
            &[
                validation_id.block_id().as_bytes(),
                &validation_id.view().get().to_be_bytes(),
                &validation_id.generation().to_be_bytes(),
                &edge_binding,
            ],
        );
        let job_checksum = epoch_transition_digest(
            "job-v10",
            &[&p.p_digest(), &p.persist_sequence().to_be_bytes()],
        );
        let host_config = epoch_transition_digest("host-v10", &[&edge_binding, &store_id]);
        let callback_checksum = epoch_transition_digest(
            "callback-v10",
            &[&confirmed.artifact_checksum(), &confirmed.overlay_checksum()],
        );
        let idempotency_key = epoch_transition_digest(
            "idempotency-v10",
            &[validation_id.block_id().as_bytes(), &accepted.delivery_digest_v0()],
        );
        let delivered_job = epoch_transition_digest(
            "delivered-job-v10",
            &[&p.p_digest(), &accepted.valid_result_checksum_v0()],
        );
        let outbox_checksum = epoch_transition_digest(
            "outbox-v10",
            &[&accepted.delivery_digest_v0(), &p.p_digest()],
        );
        ensure!(
            native_valid_result_checksum_v0(
                persistence
                    .state()
                    .payload_validation_completions()
                    .iter()
                    .find(|completion| {
                        completion.route() == route && completion.id() == validation_id
                    })
                    .context("successor Core D completion missing")?
                    .result(),
            ) == Some(accepted.valid_result_checksum_v0()),
            "successor D result checksum changed before Safety C"
        );
        let manifest = NativeValidHostManifestV0::new(
            request_fingerprint,
            job_checksum,
            host_config,
            callback_checksum,
            idempotency_key,
            delivered_job,
            outbox_checksum,
        )?;
        let transition = SafetyTransitionContextV0::native_valid(
            NativeValidTransitionV0::from_core_delivery_v0(accepted, manifest)?,
        );
        let head = self
            .runtime
            .journal
            .persist_exact_v4(self.runtime.pin, persistence, &transition)?;
        self.runtime.pin = head.pin_v4();
        let ordinary = self.ordinary_cut_v10()?;
        let application = self.runtime.checkpoint.fields().application;
        self.advance_checkpoint_v10(safety_cut_v9(&head), ordinary, application)?;
        self.runtime.journal.confirm_exact_request_v4(
            self.runtime.pin,
            persistence,
            &transition,
        )?;
        self.runtime
            .driver
            .step_v2(Input::StorageAck {
                barrier: accepted.barrier_v0(),
            })
            .map_err(|e| anyhow::anyhow!("successor Core D ACK: {e:?}"))
    }

    pub fn execute_first_proposal_v10(mut self) -> Result<(Self, Vec<Effect>)> {
        self.confirm_active_cut_v10()?;
        ensure!(
            self.pending_epoch_commit.is_none(),
            "successor native P already pending"
        );
        let delivery = self.compute_first_valid_v10()?;
        let effects = self.persist_valid_v10(
            &delivery.accepted,
            &delivery.confirmed,
            delivery.route,
            delivery.validation_id,
        )?;
        let header = delivery.prepared.header()?;
        self.pending_epoch_commit = Some(PendingEpochCommitV1 {
            prepared: delivery.prepared,
            overlay_digest: delivery.confirmed.overlay_checksum(),
            epoch: header.epoch().get(),
            view: header.view().get(),
            timestamp_ms: header.timestamp_ms(),
        });
        self.confirm_active_cut_v10()?;
        Ok((self, effects))
    }



    pub fn sign_first_vote_v10<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        self.confirm_active_cut_v10()?;
        let pending = self
            .pending_epoch_commit
            .as_ref()
            .context("successor P missing")?;
        let intent = self
            .runtime
            .driver
            .state()
            .pending_sign()
            .cloned()
            .context("successor Vote intent is not pending")?;
        let (authorizing_safety_revision, view, height, block_id) = match intent {
            SignIntent::Vote {
                authorizing_safety_revision,
                view,
                height,
                block_id,
                ..
            } => (authorizing_safety_revision, view, height, block_id),
            SignIntent::TimeoutVote { .. } => anyhow::bail!("successor pending intent is not Vote"),
        };
        ensure!(
            pending.prepared.header()?.id() == block_id,
            "successor Vote/P mismatch"
        );
        let canonical = CanonicalSignIntentV0::vote(
            self.runtime.driver.config().validator_set(),
            self.runtime.driver.config().local_validator(),
            authorizing_safety_revision,
            view,
            height,
            block_id,
        )
        .map_err(|e| anyhow::anyhow!("successor canonical Vote: {e:?}"))?;
        ensure!(
            canonical.signing_root()
                == self
                    .runtime
                    .driver
                    .state()
                    .pending_sign()
                    .context("successor Vote disappeared")?
                    .signing_root(),
            "successor canonical/Core Vote mismatch"
        );
        let before = self
            .runtime
            .ordinary
            .confirm_node_checkpoint_head_exact_v0()?;
        let prepared = &pending.prepared;
        let runtime = &mut *self.runtime;
        let SuccessorEpochRuntimeV9 {
            source,
            driver,
            journal,
            pin,
            ordinary,
            checkpoint,
            ..
        } = runtime;
        let mut guarded = FreshEpochSignatureProducerV1 {
            producer,
            expected: &canonical,
            confirm: || {
                confirm_successor_non_signer_owners_v10(
                    source,
                    driver,
                    journal,
                    *pin,
                    checkpoint,
                    prepared,
                )
            },
        };
        let signature = ordinary.sign_exact_v0(&canonical, &mut guarded)?;
        let after = ordinary.confirm_node_checkpoint_head_exact_v0()?;
        ensure!(
            after.exact_watermark().sequence() == before.exact_watermark().sequence() + 2
                && before.journal_id() == after.journal_id()
                && before.profile_checksum() == after.profile_checksum()
                && after.pending_intent().is_none(),
            "successor Vote did not persist one exact signer pair"
        );
        let mark = after.exact_watermark();
        let signed_cut = EpochOrdinaryCustodyCutV1 {
            scope: mark.scope(),
            journal_id: mark.journal_id(),
            profile_checksum: after.profile_checksum(),
            sequence: mark.sequence(),
            chain_checksum: mark.chain_checksum(),
        };
        let application = self.runtime.checkpoint.fields().application;
        self.advance_checkpoint_v10(
            self.runtime.checkpoint.fields().target_safety,
            signed_cut,
            application,
        )?;
        let signed_state = self.runtime.driver.state().clone();
        let outbound = self
            .runtime
            .driver
            .step_v2(Input::SignatureReady {
                id: trnm_consensus_core::SignId::new(canonical.signing_root()),
                signature,
            })
            .map_err(|e| anyhow::anyhow!("successor Vote delivery: {e:?}"))?;
        let [Effect::Broadcast(message)] = outbound.as_slice() else {
            anyhow::bail!("successor Vote yielded unexpected effect")
        };
        let trnm_consensus_core::OutboundMessage::Vote(vote) = message else {
            anyhow::bail!("successor signature yielded non-Vote")
        };
        vote.verify(
            self.runtime.driver.config().validator_set(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .map_err(|e| anyhow::anyhow!("successor Vote verify: {e:?}"))?;
        ensure!(
            vote.author() == canonical.author()
                && vote.signing_root() == canonical.signing_root()
                && vote.signature() == &signature
                && self.runtime.driver.state().pending_sign().is_none(),
            "successor Vote differs from persisted intent"
        );
        let effects = self
            .runtime
            .driver
            .persist_signature_release_v2(&signed_state)
            .map_err(|e| anyhow::anyhow!("successor Vote release: {e:?}"))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("successor Vote release did not persist one Safety cut")
        };
        let head = self.runtime.journal.persist_exact_v4(
            self.runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        self.runtime.pin = head.pin_v4();
        self.advance_checkpoint_v10(safety_cut_v9(&head), signed_cut, application)?;
        self.runtime.journal.confirm_exact_request_v4(
            self.runtime.pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
        )?;
        let ack = self
            .runtime
            .driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("successor Vote release ACK: {e:?}"))?;
        ensure!(ack.is_empty(), "successor Vote release ACK yielded authority");
        self.confirm_active_cut_v10()?;
        Ok((self, message.clone()))
    }

    pub fn commit_first_finality_v10(
        mut self,
        proof_bytes: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        self.confirm_active_cut_v10()?;
        ensure!(
            self.runtime.driver.state().pending_sign().is_none(),
            "successor Vote is not released"
        );
        let pending = self
            .pending_epoch_commit
            .take()
            .context("successor finality P missing")?;
        let committed = match self.application().commit_epoch_finality_bytes_v1(
            &pending.prepared,
            proof_bytes,
            budget,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                self.runtime.fenced = true;
                return Err(error.context("successor strict finality/K"));
            }
        };
        ensure!(
            committed.belongs_to_application(self.application()),
            "successor committed readback lost owner"
        );
        let head = committed.head();
        ensure!(
            head.block_id().as_bytes() == pending.prepared.header()?.id().as_bytes(),
            "successor K head differs from retained P"
        );
        let old = self.runtime.checkpoint.fields().application;
        let next = EpochApplicationCutV1 {
            block_id: *head.block_id().as_bytes(),
            height: head.height().get(),
            epoch: pending.epoch,
            view: pending.view,
            timestamp_ms: pending.timestamp_ms,
            state_root: *head.state_root().as_bytes(),
            native_store_id: old.native_store_id,
            native_commit_id: *head.commit_id().as_bytes(),
            p_sequence: pending.prepared.persist_sequence(),
            p_digest: committed.p_digest(),
            artifact_digest: pending.prepared.artifact_digest(),
            overlay_digest: pending.overlay_digest,
            commit_sequence: committed.commit_sequence(),
        };
        let ordinary = self.ordinary_cut_v10()?;
        if let Err(error) = self.advance_checkpoint_v10(
            self.runtime.checkpoint.fields().target_safety,
            ordinary,
            next,
        ) {
            self.runtime.fenced = true;
            return Err(error.context("successor K independent checkpoint CAS"));
        }
        self.pending_epoch_commit = None;
        self.confirm_active_cut_v10()?;
        Ok(self)
    }

    pub fn committed_checkpoint_v10(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(
            self.pending_validation.is_none() && self.pending_epoch_commit.is_none(),
            "successor first application unresolved"
        );
        self.confirm_active_cut_v10()
    }
}

fn confirm_successor_non_signer_owners_v10<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
>(
    source: &mut Box<EpochHandoffAttachedRuntimeV8<W, N, H>>,
    driver: &PendingEpochHostDriverV2,
    journal: &SqliteEpochSafetyJournalV4,
    pin: EpochSafetyHeadPinV4,
    checkpoint: &EpochNodeCheckpointV1,
    prepared: &trnm_native_execution_v0::PreparedNativeEpochExecutionV1,
) -> Result<()> {
    source
        .roles
        .retired
        .checkpoint_store
        .confirm_exact(checkpoint)?;
    source.confirm_native_and_custody_v8()?;
    let fresh = journal.fresh_read_v4(pin)?;
    ensure!(
        fresh.belongs_to_store_at_path_v4(journal, journal.path_v4())
            && fresh.state_v4() == driver.state()
            && safety_cut_v9(&fresh) == checkpoint.fields().target_safety,
        "successor Safety changed at key boundary"
    );
    let application = &source.roles.retired.source.application;
    ensure!(
        source.edge.belongs_to_application(application),
        "successor native owner changed at key boundary"
    );
    let confirmed = application.confirm_prepared_epoch_execution_v1(prepared)?;
    ensure!(
        confirmed.commit_sequence().is_none()
            && confirmed.prepared().p_digest() == prepared.p_digest()
            && confirmed.prepared().persist_sequence() == prepared.persist_sequence(),
        "successor native P changed at key boundary"
    );
    let app = checkpoint.fields().application;
    let head = application.confirmed_committed_head_v0()?;
    ensure!(
        head.height().get() == app.height
            && head.block_id().as_bytes() == &app.block_id
            && head.state_root().as_bytes() == &app.state_root
            && head.commit_id().as_bytes() == &app.native_commit_id,
        "successor native head changed at key boundary"
    );
    source
        .roles
        .retired
        .checkpoint_store
        .confirm_exact(checkpoint)?;
    Ok(())
}
