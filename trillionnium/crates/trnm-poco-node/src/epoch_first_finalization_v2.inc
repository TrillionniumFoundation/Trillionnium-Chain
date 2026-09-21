// Explicit, bounded private-owner continuation; the V1 entry points stay fenced.
impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0> CandidateEpochRuntimeV1<W, N> {
    fn persist_epoch_valid_delivery_v1(
        &mut self,
        accepted: &trnm_consensus_core::CoreAcceptedApplicationValidDV0,
        confirmed: &trnm_native_execution_v0::ConfirmedPreparedNativeEpochExecutionV1,
        route: trnm_consensus_core::PayloadValidationRouteV0,
        validation_id: trnm_consensus_core::ValidationId,
    ) -> Result<Vec<Effect>> {
        let persistence = accepted.persistence_request_v0();
        let p = confirmed.prepared();
        let request_fingerprint = epoch_transition_digest(
            "request",
            &[
                validation_id.block_id().as_bytes(),
                &validation_id.view().get().to_be_bytes(),
                &validation_id.generation().to_be_bytes(),
                &self.edge.authorization_id(),
            ],
        );
        let job_checksum =
            epoch_transition_digest("job", &[&p.p_digest(), &p.persist_sequence().to_be_bytes()]);
        let host_config = epoch_transition_digest(
            "host",
            &[
                &self.edge.authorization_id(),
                &self.edge.durable_checkpoint().store_id_v0(),
            ],
        );
        let callback_checksum = epoch_transition_digest(
            "callback",
            &[
                &confirmed.artifact_checksum(),
                &confirmed.overlay_checksum(),
            ],
        );
        let idempotency_key = epoch_transition_digest(
            "idempotency",
            &[
                validation_id.block_id().as_bytes(),
                &accepted.delivery_digest_v0(),
            ],
        );
        let delivered_job = epoch_transition_digest(
            "delivered-job",
            &[&p.p_digest(), &accepted.valid_result_checksum_v0()],
        );
        let outbox_checksum =
            epoch_transition_digest("outbox", &[&accepted.delivery_digest_v0(), &p.p_digest()]);
        ensure!(
            native_valid_result_checksum_v0(
                persistence
                    .state()
                    .payload_validation_completions()
                    .iter()
                    .find(|completion| {
                        completion.route() == route && completion.id() == validation_id
                    })
                    .context("epoch Core D completion missing")?
                    .result(),
            ) == Some(accepted.valid_result_checksum_v0()),
            "epoch D result checksum changed before Safety C"
        );
        let host_manifest = NativeValidHostManifestV0::new(
            request_fingerprint,
            job_checksum,
            host_config,
            callback_checksum,
            idempotency_key,
            delivered_job,
            outbox_checksum,
        )?;
        let transition = SafetyTransitionContextV0::native_valid(
            NativeValidTransitionV0::from_core_delivery_v0(accepted, host_manifest)?,
        );
        let head = self
            .journal
            .persist_exact_v1(self.pin, persistence, &transition)?;
        self.pin = head.pin_v1();
        let ordinary = self
            .checkpoint
            .fields()
            .ordinary
            .context("missing live ordinary cut")?;
        self.advance_exact_cut_v1(safety_cut(&head), ordinary)?;
        self.journal
            .confirm_exact_request_v1(self.pin, persistence, &transition)?;
        let effects = self
            .driver
            .step_v1(Input::StorageAck {
                barrier: accepted.barrier_v0(),
            })
            .map_err(|e| anyhow::anyhow!("epoch Core D/K ACK: {e:?}"))?;
        Ok(effects)
    }
}

/// A bounded live continuation which settles one first-new application block.
/// It exposes neither its private Core nor any signer or application capability.
#[must_use]
pub struct FirstEpochFinalizationRuntimeV2<
    W: ExternalSignerRetirementV1,
    N: ExternalMonotonicWatermarkV0,
> {
    runtime: Box<CandidateEpochRuntimeV1<W, N>>,
    prepared: Vec<PendingEpochCommitV1>,
    apply_authority: trnm_consensus_core::CoreIssuedApplicationFinalizationApplyAuthorityV0,
    finality_observed: bool,
    applied: bool,
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0> CandidateEpochRuntimeV1<W, N> {
    /// Consumes the exact post-Vote/pre-K first-new owner into the explicit
    /// three-block continuation. The older native-only K route is unavailable
    /// after this move, and no public downcast recreates it.
    pub fn begin_first_finalization_v2(mut self) -> Result<FirstEpochFinalizationRuntimeV2<W, N>> {
        self.confirm_current_cut_v1()?;
        self.require_first_new_phase_v1(FirstNewEpochPhaseV1::VoteReleased)?;
        let first = self
            .pending_epoch_commit
            .take()
            .context("first P missing")?;
        let confirmed = self
            .application
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        ensure!(
            confirmed.commit_sequence().is_none(),
            "first P is already committed"
        );
        let apply_authority = self
            .driver
            .issue_application_finalization_apply_authority_v1()
            .map_err(|e| anyhow::anyhow!("first apply authority: {e:?}"))?;
        ensure!(
            self.seal_authority
                .matches_application_finalization_authority_v0(&apply_authority),
            "first apply/seal authorities belong to different Core owners"
        );
        Ok(FirstEpochFinalizationRuntimeV2 {
            runtime: Box::new(self),
            prepared: vec![first],
            apply_authority,
            finality_observed: false,
            applied: false,
        })
    }
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    FirstEpochFinalizationRuntimeV2<W, N>
{
    fn require_collecting(&mut self) -> Result<()> {
        ensure!(
            !self.finality_observed && !self.applied,
            "first finality collection is closed"
        );
        self.runtime.confirm_current_cut_v1()?;
        ensure!(
            self.runtime.pending_validation.is_none()
                && self.runtime.pending_epoch_commit.is_none()
                && self.runtime.driver.state().pending_sign().is_none()
                && self.runtime.driver.state().pending_finalize().is_none()
                && self
                    .runtime
                    .driver
                    .state()
                    .payload_validation_obligations()
                    .is_empty(),
            "first finality continuation has an unresolved operation"
        );
        Ok(())
    }

    fn persist_ordinary_effects(&mut self, effects: &[Effect]) -> Result<Vec<Effect>> {
        let [Effect::PersistSafetyState(request)] = effects else {
            anyhow::bail!("first continuation expected one Core persistence barrier");
        };
        let r = &mut self.runtime;
        let context = SafetyTransitionContextV0::ordinary();
        let head = r.journal.persist_exact_v1(r.pin, request, &context)?;
        r.pin = head.pin_v1();
        let ordinary = r
            .checkpoint
            .fields()
            .ordinary
            .context("missing ordinary custody")?;
        r.advance_exact_cut_v1(safety_cut(&head), ordinary)?;
        r.journal
            .confirm_exact_request_v1(r.pin, request, &context)?;
        r.driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("first continuation ACK: {e:?}"))
    }

    /// Admit and execute one complete ordinary child against the exact retained
    /// Prepared parent. This returns before invoking the signer.
    pub fn execute_child_proposal_v2(self, proposal: SignedProposalV0) -> Result<Self> {
        self.execute_application_child_v4(proposal, None)
    }

    fn execute_application_child_v4(
        mut self,
        proposal: SignedProposalV0,
        checkpoint_commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
    ) -> Result<Self> {
        self.require_collecting()?;
        ensure!(self.prepared.len() < 3, "first continuation child bound");
        let parent = self
            .prepared
            .last()
            .context("first continuation parent missing")?;
        let parent_header = parent.prepared.header()?;
        ensure!(
            proposal.block().header().block_kind()
                == if checkpoint_commitment.is_some() {
                    BlockKind::EpochCheckpoint
                } else {
                    BlockKind::Regular
                }
                && proposal.block().header().parent_id() == parent_header.id()
                && proposal.block().header().height().get()
                    == parent_header
                        .height()
                        .get()
                        .checked_add(1)
                        .context("child height overflow")?,
            "application continuation requires an exact child of the expected kind"
        );
        let expected_block = proposal.block().id();
        let effects = self
            .runtime
            .driver
            .step_v1(Input::Proposal(Box::new(proposal)))
            .map_err(|e| anyhow::anyhow!("child Core proposal: {e:?}"))?;
        let released = self.persist_ordinary_effects(&effects)?;
        let mut validation = None;
        for effect in released {
            match effect {
                Effect::ValidatePayload(request) if validation.is_none() => {
                    validation = Some(request)
                }
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("child proposal released an unexpected effect"),
            }
        }
        let request = validation.context("child Core validation missing")?;
        let (route, id, block, witness, permit) = request
            .try_claim()
            .map_err(|_| anyhow::anyhow!("child validation already claimed"))?
            .into_parts();
        ensure!(
            route == trnm_consensus_core::PayloadValidationRouteV0::Proposal
                && block.id() == expected_block
                && witness.exact_header() == Some(&parent_header),
            "child validation source/parent substitution"
        );
        let parent = &self
            .prepared
            .last()
            .context("child native parent missing")?
            .prepared;
        let payload = decode_application_payload_v0_exact(
            block.application_payload(),
            self.runtime.edge.new_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("child payload: {e:?}"))?;
        let h = block.header();
        let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            trnm_native_application::Hash32V0::new(*h.payload_root().as_bytes()),
            trnm_native_application::StateRootV0::new(*h.state_root().as_bytes())?,
            trnm_native_application::ReceiptsRootV0::new(*h.receipts_root().as_bytes())?,
            trnm_native_application::Hash32V0::new(*h.evidence_root().as_bytes()),
        )?;
        let config = self.runtime.application.config_v0();
        let execution = trnm_native_application::NativeBlockExecutionRequestV0::new(
            trnm_native_application::ChainIdV0::new(config.chain_id_v0())?,
            trnm_native_application::GenesisHashV0::new(config.genesis_hash_v0())?,
            parent.overlay_parent_head()?,
            trnm_native_application::BlockIdV0::new(*h.id().as_bytes())?,
            trnm_native_application::HeightV0::new(h.height().get()),
            h.timestamp_ms(),
            trnm_native_application::ValidatorSetIdV0::new(*h.validator_set_id().as_bytes())?,
            payload.transactions().to_vec(),
            expected,
        )?;
        let prepared = self
            .runtime
            .application
            .execute_epoch_descendant_v1(parent, execution, h)?;
        let confirmed = self
            .runtime
            .application
            .confirm_prepared_epoch_execution_v1(&prepared)?;
        let (stored_payload, receipts) = confirmed.application_payload_and_receipts()?;
        ensure!(
            confirmed.prepared().header()? == *h
                && stored_payload == payload
                && confirmed.commit_sequence().is_none(),
            "child P readback differs"
        );
        let evidence = block
            .evidence_objects()
            .iter()
            .map(|bytes| {
                decode_double_vote_evidence_v0_exact(bytes, self.runtime.edge.new_validator_set())
                    .map_err(|e| anyhow::anyhow!("child evidence: {e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let body = BlockBodyV0::new(payload, evidence)
            .map_err(|e| anyhow::anyhow!("child body: {e:?}"))?;
        let commitments = if let Some(expected) = checkpoint_commitment {
            body.verify_evidence(
                self.runtime.edge.new_validator_set(),
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("checkpoint evidence: {e:?}"))?;
            confirm_checkpoint_selection_v4(
                &self.runtime.application,
                &self.runtime.edge,
                &self.runtime.checkpoint,
                h,
            )?;
            body.validate_checkpoint_static_commitments(
                h,
                &receipts,
                self.runtime.edge.new_parameters(),
                trnm_consensus_types::StateRoot::new(
                    *confirmed
                        .prepared()
                        .overlay_parent_head()?
                        .state_root()
                        .as_bytes(),
                ),
                expected,
            )
            .map_err(|e| anyhow::anyhow!("checkpoint commitments: {e:?}"))?
            .application_commitments_v1()
        } else {
            body.validate_ordinary_commitments(
                h,
                &receipts,
                self.runtime.edge.new_parameters(),
                self.runtime.edge.new_validator_set(),
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("child commitments: {e:?}"))?
        };
        let artifact = trnm_consensus_core::ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(h.id(), parent_header.id(), confirmed.overlay_checksum()),
            confirmed.artifact_checksum(),
        );
        let sealed = self
            .runtime
            .seal_authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact);
        let accepted = self
            .runtime
            .driver
            .step_application_sealed_valid_to_delivery_v1(&sealed)
            .map_err(|e| anyhow::anyhow!("child Core D: {e:?}"))?;
        let effects = self
            .runtime
            .persist_epoch_valid_delivery_v1(&accepted, &confirmed, route, id)?;
        ensure!(
            matches!(effects.as_slice(), [Effect::RequestSignature { .. }]),
            "child Valid must release exactly its Vote obligation"
        );
        self.runtime.pending_epoch_commit = Some(PendingEpochCommitV1 {
            prepared,
            overlay_digest: confirmed.overlay_checksum(),
            epoch: h.epoch().get(),
            view: h.view().get(),
            timestamp_ms: h.timestamp_ms(),
        });
        self.runtime.confirm_current_cut_v1()?;
        Ok(self)
    }

    /// Persist and release this child's actual Core Vote through the same
    /// private custody/key-boundary checks as the first-new Vote.
    pub fn sign_child_vote_v2<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        ensure!(
            !self.finality_observed && !self.applied && self.prepared.len() < 3,
            "first continuation signing phase"
        );
        let (mut runtime, vote) = (*self.runtime).sign_pending_epoch_vote_v1(producer)?;
        let prepared = runtime
            .pending_epoch_commit
            .take()
            .context("signed child P missing")?;
        self.prepared.push(prepared);
        self.runtime = Box::new(runtime);
        Ok((self, vote))
    }

    /// Let Core authenticate the exact third QC and derive its own durable
    /// first-new finalization queue. Caller proof headers cannot create it.
    pub fn observe_first_finality_qc_v2(
        mut self,
        certificate: trnm_consensus_types::QuorumCertificate,
    ) -> Result<Self> {
        self.require_collecting()?;
        ensure!(
            self.prepared.len() == 3,
            "first finality requires three real executions"
        );
        let third = self.prepared[2].prepared.header()?;
        ensure!(
            certificate.block_id() == third.id(),
            "first finality QC names another block"
        );
        let effects = self
            .runtime
            .driver
            .step_v1(Input::QuorumCertificate(certificate))
            .map_err(|e| anyhow::anyhow!("third QC: {e:?}"))?;
        let released = self.persist_ordinary_effects(&effects)?;
        let first = self.prepared[0].prepared.header()?;
        let mut finalize = None;
        for effect in released {
            match effect {
                Effect::Finalize(value) if finalize.is_none() => finalize = Some(value),
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("third QC released an unexpected effect"),
            }
        }
        let finalize = finalize.context("Core did not emit first finalization")?;
        ensure!(
            finalize.proof().finalized_block().header() == &first
                && self.runtime.driver.state().pending_finalization() == Some(finalize.as_ref()),
            "Core first queue-front substitution"
        );
        self.runtime.confirm_current_cut_v1()?;
        self.finality_observed = true;
        Ok(self)
    }

    /// Read-only composite cut after successful application settlement.
    pub fn settled_checkpoint_v2(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(self.applied, "first application has not settled");
        self.runtime.confirm_current_cut_v1()?;
        ensure!(
            self.runtime.driver.state().finalized()
                == self.runtime.driver.state().application_applied()
                && self.runtime.driver.state().pending_finalize().is_none(),
            "first Core application is unsettled"
        );
        Ok(self.runtime.checkpoint)
    }
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    FirstEpochFinalizationRuntimeV2<W, N>
{
    /// Commit only Core's exact durable front, then persist its typed apply
    /// receipt and independently checkpoint every owner before acknowledging.
    pub fn apply_first_finalization_v2(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        ensure!(
            self.finality_observed && !self.applied && self.prepared.len() == 3,
            "first application apply phase"
        );
        let r = &mut self.runtime;
        r.confirm_current_cut_v1()?;
        let first = &self.prepared[0];
        let header = first.prepared.header()?;
        let before = r
            .application
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        ensure!(
            before.commit_sequence().is_none(),
            "first application was committed outside Core apply"
        );
        let permit = r
            .driver
            .issue_application_finalization_permit_v1()
            .map_err(|e| anyhow::anyhow!("first Core apply permit: {e:?}"))?;
        ensure!(
            self.apply_authority
                .matches_application_finalization_permit_v0(&permit)
                && permit.finalization().proof().finalized_block().header() == &header
                && permit
                    .finalization()
                    .target_overlay_ref()
                    .overlay_checksum()
                    == before.overlay_checksum()
                && permit
                    .finalization()
                    .target_overlay_ref()
                    .parent_block_id()
                    .as_bytes()
                    == first.prepared.application_parent().block_id().as_bytes(),
            "first apply permit/native P mismatch"
        );
        let mut sources = r
            .driver
            .state()
            .payload_validation_completions()
            .iter()
            .filter(|source| {
                source.id().block_id() == header.id()
                    && source.result().artifact_ref().is_some_and(|artifact| {
                        artifact.overlay() == permit.finalization().target_overlay_ref()
                            && artifact.source_artifact_checksum() == before.artifact_checksum()
                    })
            });
        let source = sources
            .next()
            .context("first apply lacks its exact Core Valid completion")?;
        let route = source.route();
        let id = source.id();
        let accepted_source = native_valid_result_checksum_v0(source.result())
            .context("first apply source is not Valid")?;
        ensure!(
            sources.next().is_none(),
            "first apply has ambiguous Core Valid provenance"
        );
        let finalization_checksum =
            trnm_consensus_core::native_finalization_applied_checksum_v0(permit.finalization())
                .map_err(|e| anyhow::anyhow!("first finalization checksum: {e:?}"))?;
        let proof = permit
            .finalization()
            .proof()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("first finality bytes: {e:?}"))?;
        let prior = r.application.confirmed_committed_head_v0()?;
        ensure!(
            &prior == first.prepared.application_parent(),
            "first apply parent changed"
        );
        let committed =
            r.application
                .commit_epoch_finality_bytes_v1(&first.prepared, &proof, budget)?;
        let fresh = r
            .application
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        let current = r.application.confirmed_committed_head_v0()?;
        ensure!(
            committed.belongs_to_application(&r.application)
                && fresh.belongs_to_application_at_path(&r.application, r.application.path())
                && committed.head() == &current
                && fresh.prepared().overlay_parent_head()? == current
                && fresh.commit_sequence() == Some(committed.commit_sequence())
                && fresh.prepared().p_digest() == committed.p_digest()
                && fresh.artifact_checksum() == before.artifact_checksum()
                && fresh.overlay_checksum() == before.overlay_checksum(),
            "first committed P/readback mismatch"
        );
        let config = r.application.config_v0();
        let host = epoch_transition_digest(
            "apply-v2-owner",
            &[
                config.chain_id_v0().as_bytes(),
                &config.genesis_hash_v0(),
                &config.store_id(),
                &config.chain_descriptor_hash_v0(),
                &r.edge.authorization_id(),
            ],
        );
        let prior_digest = epoch_application_head_digest_v2(&prior);
        let new_digest = epoch_application_head_digest_v2(&current);
        let applied_job = epoch_transition_digest(
            "apply-v2-committed-p",
            &[
                &fresh.prepared().p_digest(),
                &fresh.prepared().persist_sequence().to_be_bytes(),
                &committed.commit_sequence().to_be_bytes(),
                &fresh.artifact_checksum(),
                &fresh.overlay_checksum(),
                &new_digest,
            ],
        );
        let receipt_digest = epoch_transition_digest(
            "apply-v2-readback",
            &[
                &finalization_checksum,
                id.block_id().as_bytes(),
                &id.view().get().to_be_bytes(),
                &id.generation().to_be_bytes(),
                &accepted_source,
                &applied_job,
                &prior_digest,
                &new_digest,
            ],
        );
        let readback = self
            .apply_authority
            .application_store_apply_readback_v0(
                &permit,
                route,
                id,
                header.height().get(),
                host,
                prior_digest,
                new_digest,
                fresh.artifact_checksum(),
                accepted_source,
                applied_job,
                receipt_digest,
            )
            .map_err(|e| anyhow::anyhow!("first application readback: {e:?}"))?;
        let receipt = self
            .apply_authority
            .receipt_after_application_store_apply_v0(permit, readback)
            .map_err(|e| anyhow::anyhow!("first application receipt: {:?}", e.into_parts().0))?;
        let effects = r
            .driver
            .step_application_finalization_receipt_v1(receipt)
            .map_err(|e| anyhow::anyhow!("first Core applied receipt: {:?}", e.into_parts().0))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("first apply did not create one Safety barrier");
        };
        let manifest = request
            .native_finalization_applied_v0()
            .context("first apply lacks typed Core manifest")?;
        let facts = manifest.application_store_readback_v0();
        let context = SafetyTransitionContextV0::native_finalization_applied(
            trnm_consensus_safety_store::NativeFinalizationAppliedTransitionV0::new(
                facts.source_route(),
                facts.source_validation_id(),
                facts.ordinal(),
                facts.application_host_config_ref(),
                facts.finalization_checksum(),
                facts.prior_head_checksum(),
                facts.new_head_checksum(),
                facts.source_artifact_checksum(),
                facts.accepted_source_checksum(),
                facts.applied_job_row_checksum(),
                facts.receipt_row_checksum(),
                manifest.post_ack_action_v0().code(),
                request.state().revision(),
            )?,
        );
        let safety = r.journal.persist_exact_v1(r.pin, request, &context)?;
        r.pin = safety.pin_v1();
        r.journal
            .confirm_exact_request_v1(r.pin, request, &context)?;
        let application = EpochApplicationCutV1 {
            block_id: *current.block_id().as_bytes(),
            height: current.height().get(),
            epoch: first.epoch,
            view: first.view,
            timestamp_ms: first.timestamp_ms,
            state_root: *current.state_root().as_bytes(),
            native_store_id: config.store_id(),
            native_commit_id: *current.commit_id().as_bytes(),
            p_sequence: first.prepared.persist_sequence(),
            p_digest: committed.p_digest(),
            artifact_digest: fresh.artifact_checksum(),
            overlay_digest: fresh.overlay_checksum(),
            commit_sequence: committed.commit_sequence(),
        };
        let ordinary = r
            .checkpoint
            .fields()
            .ordinary
            .context("first apply ordinary custody missing")?;
        r.advance_exact_cut_with_application_v1(safety_cut(&safety), ordinary, application)?;
        // Confirm the exact opaque request again immediately before ACK.
        r.journal
            .confirm_exact_request_v1(r.pin, request, &context)?;
        let released = r
            .driver
            .step_v1(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("first application ACK: {e:?}"))?;
        ensure!(
            released
                .iter()
                .all(|effect| matches!(effect, Effect::ArmViewTimer { .. })),
            "first application ACK released an unexpected operation"
        );
        ensure!(
            r.driver.state().application_applied().block_id() == header.id()
                && r.driver.state().application_applied() == r.driver.state().finalized()
                && r.driver.state().pending_finalize().is_none()
                && r.driver.state().finalization_queue().is_empty()
                && r.driver.state().pending_sign().is_none(),
            "first Core application did not settle"
        );
        r.confirm_current_cut_v1()?;
        self.applied = true;
        Ok(self)
    }
}

fn epoch_application_head_digest_v2(head: &trnm_native_application::ApplicationHeadV0) -> [u8; 32] {
    epoch_transition_digest(
        "apply-v2-head",
        &[
            &head.height().get().to_be_bytes(),
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ],
    )
}

// Repeated immediately before and after the key producer, after external
// callbacks. An unchanged committed parent does not prove that its child P
// still exists or is the P accepted by this exact durable Core completion.
fn confirm_pending_vote_native_v2(
    driver: &PendingEpochHostDriverV1,
    application: &DurableNativeApplicationV0,
    prepared: Option<&PreparedNativeEpochExecutionV1>,
) -> Result<()> {
    let Some(SignIntent::Vote {
        block_id,
        height,
        view,
        ..
    }) = driver.state().pending_sign()
    else {
        ensure!(
            prepared.is_none(),
            "unexpected native P for non-Vote key boundary"
        );
        return Ok(());
    };
    let prepared = prepared.context("Vote key boundary lacks retained native P")?;
    let confirmed = application.confirm_prepared_epoch_execution_v1(prepared)?;
    let header = confirmed.prepared().header()?;
    ensure!(
        header.id() == *block_id
            && header.height() == *height
            && header.view() == *view
            && confirmed.prepared().p_digest() == prepared.p_digest()
            && confirmed.commit_sequence().is_none()
            && confirmed.belongs_to_application_at_path(application, application.path()),
        "Vote key boundary native P changed"
    );
    let overlay = if header.block_kind() == BlockKind::EpochHandoff {
        BlockIdOverlayRefV0::for_epoch_application_v1(
            header.id(),
            BlockId::new(*prepared.application_parent().block_id().as_bytes()),
            BlockId::new(prepared.consensus_parent_id()),
            driver
                .state()
                .epoch_state_v1()
                .context("Vote epoch context missing")?
                .activation_binding(),
            confirmed.overlay_checksum(),
        )
        .map_err(|e| anyhow::anyhow!("Vote epoch overlay: {e:?}"))?
    } else {
        BlockIdOverlayRefV0::new(
            header.id(),
            header.parent_id(),
            confirmed.overlay_checksum(),
        )
    };
    ensure!(
        driver
            .state()
            .payload_validation_completions()
            .iter()
            .filter(|source| {
                source.id().block_id() == *block_id
                    && source.id().view() == *view
                    && source.result().artifact_ref().is_some_and(|artifact| {
                        artifact.overlay() == overlay
                            && artifact.source_artifact_checksum() == confirmed.artifact_checksum()
                    })
            })
            .count()
            == 1,
        "Vote key boundary lacks exact durable Core Valid provenance"
    );
    Ok(())
}

struct PreparedEpochValidDeliveryV2 {
    prepared: PreparedNativeEpochExecutionV1,
    confirmed: trnm_native_execution_v0::ConfirmedPreparedNativeEpochExecutionV1,
    accepted: Box<trnm_consensus_core::CoreAcceptedApplicationValidDV0>,
    route: trnm_consensus_core::PayloadValidationRouteV0,
    validation_id: trnm_consensus_core::ValidationId,
}
impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0> CandidateEpochRuntimeV1<W, N> {
    #[inline(never)]
    fn compute_admitted_epoch_valid_v2(&mut self) -> Result<Box<PreparedEpochValidDeliveryV2>> {
        let request = self
            .pending_validation
            .take()
            .context("epoch proposal validation is not pending")?;
        let claimed = request.try_claim().map_err(|_| {
            anyhow::anyhow!("epoch proposal validation request was already claimed")
        })?;
        let (route, validation_id, block, parent, permit) = claimed.into_parts();
        ensure!(
            route == trnm_consensus_core::PayloadValidationRouteV0::Proposal,
            "epoch execution requires the Proposal validation route"
        );
        ensure!(
            block.header().block_kind() == BlockKind::EpochHandoff
                && block.header().height().get() == self.edge.first_application_height(),
            "epoch execution received a non-first-new block"
        );
        ensure!(
            parent.consensus_parent_tip_v1().block_id().as_bytes()
                == self.edge.consensus_parent().id().as_bytes(),
            "epoch execution parent witness differs from authenticated edge"
        );
        let application_parent = self.edge.application_parent();
        ensure!(
            parent.tip().block_id().as_bytes() == application_parent.block_id().as_bytes()
                && parent.tip().height().get() == application_parent.height().get(),
            "epoch execution application parent witness differs from authenticated edge"
        );

        let payload = decode_application_payload_v0_exact(
            block.application_payload(),
            self.driver.config().consensus_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("epoch payload decode: {e:?}"))?;
        let native_request = self.edge.preview_request_v1(
            block.header().timestamp_ms(),
            payload.transactions().to_vec(),
        )?;
        let preview = self
            .application
            .preview_epoch_block_v1(&self.edge, &native_request)?;
        ensure!(
            *block.header().payload_root().as_bytes() == *preview.payload_root().as_bytes()
                && *block.header().state_root().as_bytes() == *preview.post_state_root().as_bytes()
                && *block.header().receipts_root().as_bytes()
                    == *preview.receipts_root().as_bytes()
                && *block.header().evidence_root().as_bytes()
                    == *preview.evidence_root().as_bytes(),
            "epoch proposal roots differ from deterministic native preview"
        );
        let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            trnm_native_application::Hash32V0::new(*preview.payload_root().as_bytes()),
            trnm_native_application::StateRootV0::new(*preview.post_state_root().as_bytes())?,
            trnm_native_application::ReceiptsRootV0::new(*preview.receipts_root().as_bytes())?,
            trnm_native_application::Hash32V0::new(*preview.evidence_root().as_bytes()),
        )?;
        let execution_request = trnm_native_application::NativeEpochBlockExecutionRequestV1::new(
            native_request,
            trnm_native_application::BlockIdV0::new(*block.id().as_bytes())?,
            expected,
        )?;
        let prepared = self.application.execute_epoch_block_v1(
            &self.edge,
            execution_request,
            block.header(),
        )?;
        let confirmed = self
            .application
            .confirm_prepared_epoch_execution_v1(&prepared)?;
        ensure!(
            confirmed.prepared().header()? == *block.header(),
            "epoch P readback header substitution"
        );
        let (stored_payload, receipts) = confirmed.application_payload_and_receipts()?;
        ensure!(
            stored_payload == payload,
            "epoch P readback payload substitution"
        );
        let evidence = block
            .evidence_objects()
            .iter()
            .map(|encoded| {
                decode_double_vote_evidence_v0_exact(encoded, self.edge.new_validator_set())
                    .map_err(|e| anyhow::anyhow!("epoch evidence decode: {e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let body = BlockBodyV0::new(payload, evidence)
            .map_err(|e| anyhow::anyhow!("epoch body construction: {e:?}"))?;
        let commitments = body
            .validate_epoch_handoff_commitments_v1(
                block.header(),
                &receipts,
                self.edge.new_parameters(),
                block.header().state_root(),
                self.edge.new_validator_set(),
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("epoch commitment validation: {e:?}"))?;
        let artifact = trnm_consensus_core::ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::for_epoch_application_v1(
                block.id(),
                BlockId::new(*self.edge.application_parent().block_id().as_bytes()),
                self.edge.consensus_parent().id(),
                self.driver
                    .state()
                    .epoch_state_v1()
                    .context("epoch Core state lacks activation binding")?
                    .activation_binding(),
                confirmed.overlay_checksum(),
            )
            .map_err(|e| anyhow::anyhow!("epoch artifact binding: {e:?}"))?,
            confirmed.artifact_checksum(),
        );
        let proof = self.seal_authority.seal_after_application_store_commit_v0(
            permit,
            commitments,
            artifact,
        );
        let accepted = self
            .driver
            .step_application_sealed_valid_to_delivery_v1(&proof)
            .map_err(|e| anyhow::anyhow!("epoch Core D: {e:?}"))?;
        Ok(Box::new(PreparedEpochValidDeliveryV2 {
            prepared,
            confirmed,
            accepted: Box::new(accepted),
            route,
            validation_id,
        }))
    }
}
