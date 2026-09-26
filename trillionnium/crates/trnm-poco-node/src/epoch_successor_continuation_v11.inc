// Same-owner successor continuation. This is not a new consensus protocol: it
// drives PendingEpochHostDriverV2 through the same proposal/Valid/Vote/finality
// sequence already used by V2 and keeps journal4/native/checkpoint owners joined.
#[must_use]
pub struct SuccessorFinalizationRuntimeV11<
    W: ExternalSignerRetirementV1,
    N: ExternalSignerRetirementV1,
    H: ExternalMonotonicWatermarkV0,
    O: ExternalMonotonicWatermarkV0,
> {
    inner: SuccessorFirstApplicationRuntimeV10<W, N, H, O>,
    prepared: Vec<PendingEpochCommitV1>,
    apply_authority: trnm_consensus_core::CoreIssuedApplicationFinalizationApplyAuthorityV0,
    finality_observed: bool,
    checkpoint_selection: Option<Box<trnm_native_execution_v0::ComputedLaterEpochSelectionV1>>,
    seals: Vec<SignedProposalV0>,
    signed_seals: usize,
    pre_handoff: Option<Box<trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1>>,
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
        O: ExternalMonotonicWatermarkV0,
    > SuccessorFirstApplicationRuntimeV10<W, N, H, O>
{
    /// Consume the post-Vote first-new owner. Native K is deliberately still
    /// pending; only Core's own later Finalize front may authorize the commit.
    pub fn begin_finalization_v11(
        mut self,
    ) -> Result<SuccessorFinalizationRuntimeV11<W, N, H, O>> {
        self.confirm_active_cut_v10()?;
        ensure!(
            self.pending_validation.is_none()
                && self.pending_epoch_commit.is_some()
                && self.runtime.driver.state().pending_sign().is_none()
                && self.runtime.driver.state().pending_finalize().is_none(),
            "successor finalization requires one released first-new Vote"
        );
        let first = self
            .pending_epoch_commit
            .take()
            .context("successor finalization first P missing")?;
        let confirmed = self
            .application()
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        ensure!(
            confirmed.commit_sequence().is_none(),
            "successor first P committed before Core finalization"
        );
        let apply_authority = self
            .runtime
            .driver
            .issue_application_finalization_apply_authority_v2()
            .map_err(|e| anyhow::anyhow!("successor apply authority: {e:?}"))?;
        ensure!(
            self.seal_authority
                .matches_application_finalization_authority_v0(&apply_authority),
            "successor seal/apply authority mismatch"
        );
        Ok(SuccessorFinalizationRuntimeV11 {
            inner: self,
            prepared: vec![first],
            apply_authority,
            finality_observed: false,
            checkpoint_selection: None,
            seals: Vec::new(),
            signed_seals: 0,
            pre_handoff: None,
        })
    }
}

impl<
        W: ExternalSignerRetirementV1,
        N: ExternalSignerRetirementV1,
        H: ExternalMonotonicWatermarkV0,
        O: ExternalMonotonicWatermarkV0,
    > SuccessorFinalizationRuntimeV11<W, N, H, O>
{
    fn persist_ordinary_effects_v11(&mut self, effects: &[Effect]) -> Result<Vec<Effect>> {
        let [Effect::PersistSafetyState(request)] = effects else {
            anyhow::bail!("successor continuation expected one persistence barrier")
        };
        let context = SafetyTransitionContextV0::ordinary();
        let head = self
            .inner
            .runtime
            .journal
            .persist_exact_v4(self.inner.runtime.pin, request, &context)?;
        self.inner.runtime.pin = head.pin_v4();
        let ordinary = self.inner.ordinary_cut_v10()?;
        let application = self.inner.runtime.checkpoint.fields().application;
        self.inner
            .advance_checkpoint_v10(safety_cut_v9(&head), ordinary, application)?;
        self.inner.runtime.journal.confirm_exact_request_v4(
            self.inner.runtime.pin,
            request,
            &context,
        )?;
        self.inner
            .runtime
            .driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("successor continuation ACK: {e:?}"))
    }

    /// Execute one real ordinary/checkpoint child. It returns before any key use.
    fn execute_child_v11(
        mut self,
        proposal: SignedProposalV0,
        checkpoint_commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
    ) -> Result<Self> {
        self.inner.confirm_active_cut_v10()?;
        ensure!(
            !self.finality_observed
                && self.prepared.len() < 3
                && self.seals.is_empty()
                && self.checkpoint_selection.is_none()
                && self.inner.pending_epoch_commit.is_none(),
            "successor child collection phase"
        );
        let parent_header = self
            .prepared
            .last()
            .context("successor child parent missing")?
            .prepared
            .header()?;
        let header = proposal.block().header();
        ensure!(
            header.block_kind()
                == if checkpoint_commitment.is_some() {
                    BlockKind::EpochCheckpoint
                } else {
                    BlockKind::Regular
                }
                && header.parent_id() == parent_header.id()
                && parent_header.height().checked_next().ok() == Some(header.height()),
            "successor child geometry"
        );
        let expected_block = proposal.block().id();
        let effects = self
            .inner
            .runtime
            .driver
            .step_v2(Input::Proposal(Box::new(proposal)))
            .map_err(|e| anyhow::anyhow!("successor child proposal: {e:?}"))?;
        let released = self.persist_ordinary_effects_v11(&effects)?;
        let mut validation = None;
        for effect in released {
            match effect {
                Effect::ValidatePayload(request) if validation.is_none() => validation = Some(request),
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("successor child proposal released unexpected effect"),
            }
        }
        let (route, id, block, witness, permit) = validation
            .context("successor child validation missing")?
            .try_claim()
            .map_err(|_| anyhow::anyhow!("successor child validation already claimed"))?
            .into_parts();
        ensure!(
            route == trnm_consensus_core::PayloadValidationRouteV0::Proposal
                && block.id() == expected_block
                && witness.exact_header() == Some(&parent_header),
            "successor child validation source changed"
        );
        let parent = &self
            .prepared
            .last()
            .context("successor child parent disappeared after durable ACK")?
            .prepared;
        let params = self.inner.runtime.driver.config().consensus_parameters();
        let set = self.inner.runtime.driver.config().validator_set();
        let payload = decode_application_payload_v0_exact(block.application_payload(), params)
            .map_err(|e| anyhow::anyhow!("successor child payload: {e:?}"))?;
        let h = block.header();
        let request = trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
            trnm_native_application::ChainIdV0::new(set.chain_id().as_str())?,
            trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes())?,
            parent.overlay_parent_head()?,
            trnm_native_application::HeightV0::new(h.height().get()),
            h.timestamp_ms(),
            trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes())?,
            payload.transactions().to_vec(),
        )?;
        let preview = self.inner.application().preview_epoch_descendant_v1(parent, &request)?;
        ensure!(
            h.payload_root().as_bytes() == preview.payload_root().as_bytes()
                && h.state_root().as_bytes() == preview.post_state_root().as_bytes()
                && h.receipts_root().as_bytes() == preview.receipts_root().as_bytes()
                && h.evidence_root().as_bytes() == preview.evidence_root().as_bytes(),
            "successor child roots differ from native preview"
        );
        let execution = trnm_native_application::NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            trnm_native_application::BlockIdV0::new(*h.id().as_bytes())?,
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                trnm_native_application::Hash32V0::new(*preview.payload_root().as_bytes()),
                trnm_native_application::StateRootV0::new(*preview.post_state_root().as_bytes())?,
                trnm_native_application::ReceiptsRootV0::new(*preview.receipts_root().as_bytes())?,
                trnm_native_application::Hash32V0::new(*preview.evidence_root().as_bytes()),
            )?,
        )?;
        let prepared = self
            .inner
            .application()
            .execute_epoch_descendant_v1(parent, execution, h)?;
        let confirmed = self
            .inner
            .application()
            .confirm_prepared_epoch_execution_v1(&prepared)?;
        let (stored_payload, receipts) = confirmed.application_payload_and_receipts()?;
        ensure!(
            confirmed.prepared().header()? == *h
                && stored_payload == payload
                && confirmed.commit_sequence().is_none(),
            "successor child P changed"
        );
        let evidence = block
            .evidence_objects()
            .iter()
            .map(|bytes| {
                decode_double_vote_evidence_v0_exact(bytes, set)
                    .map_err(|e| anyhow::anyhow!("successor child evidence: {e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let body = BlockBodyV0::new(payload, evidence)
            .map_err(|e| anyhow::anyhow!("successor child body: {e:?}"))?;
        let commitments = if let Some(expected) = checkpoint_commitment {
            body.verify_evidence(set, &trnm_consensus_crypto::StrictEd25519Verifier)
                .map_err(|e| anyhow::anyhow!("successor checkpoint evidence: {e:?}"))?;
            body.validate_checkpoint_static_commitments(
                h,
                &receipts,
                params,
                trnm_consensus_types::StateRoot::new(
                    *confirmed.prepared().overlay_parent_head()?.state_root().as_bytes(),
                ),
                expected,
            )
            .map_err(|e| anyhow::anyhow!("successor checkpoint commitments: {e:?}"))?
            .application_commitments_v1()
        } else {
            body.validate_ordinary_commitments(
                h,
                &receipts,
                params,
                set,
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("successor child commitments: {e:?}"))?
        };
        let artifact = trnm_consensus_core::ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(h.id(), parent_header.id(), confirmed.overlay_checksum()),
            confirmed.artifact_checksum(),
        );
        let sealed = self
            .inner
            .seal_authority
            .seal_after_application_store_commit_v0(permit, commitments, artifact);
        let accepted = self
            .inner
            .runtime
            .driver
            .step_application_sealed_valid_to_delivery_v2(&sealed)
            .map_err(|e| anyhow::anyhow!("successor child Core D: {e:?}"))?;
        let effects = self
            .inner
            .persist_valid_v10(&accepted, &confirmed, route, id)?;
        ensure!(
            matches!(effects.as_slice(), [Effect::RequestSignature { .. }]),
            "successor child Valid must release exactly one Vote"
        );
        self.inner.pending_epoch_commit = Some(PendingEpochCommitV1 {
            prepared,
            overlay_digest: confirmed.overlay_checksum(),
            epoch: h.epoch().get(),
            view: h.view().get(),
            timestamp_ms: h.timestamp_ms(),
        });
        self.inner.confirm_active_cut_v10()?;
        Ok(self)
    }

    pub fn execute_ordinary_child_v11(self, proposal: SignedProposalV0) -> Result<Self> {
        self.execute_child_v11(proposal, None)
    }

    /// Prepare the next checkpoint from this same live successor's committed
    /// cutoff. Selection is reproduced from the native owner before any Core
    /// mutation; a proposed hash does not select the next validator set.
    pub fn execute_checkpoint_child_v11(mut self, proposal: SignedProposalV0) -> Result<Self> {
        let checkpoint = self.settled_checkpoint_v11()?;
        ensure!(
            self.inner.pending_epoch_commit.is_none(),
            "successor checkpoint has a pending application obligation"
        );
        let commitment = confirm_checkpoint_selection_at_active_cut_v4(
            self.inner.application(),
            &checkpoint,
            proposal.block().header(),
            self.inner.runtime.driver.config().validator_set(),
            self.inner.runtime.driver.config().consensus_parameters(),
        )?;
        let selection = self.inner.application().compute_later_epoch_selection_v1(
            trnm_native_application::HeightV0::new(checkpoint.fields().application.height),
        )?;
        ensure!(selection.next_epoch_commitment().id() == commitment, "successor selection changed");
        let mut owner = self.execute_child_v11(proposal, Some(commitment))?;
        owner.checkpoint_selection = Some(Box::new(selection));
        Ok(owner)
    }

    pub fn sign_child_vote_v11<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        ensure!(
            !self.finality_observed && self.seals.is_empty()
                && self.inner.pending_epoch_commit.is_some(),
            "successor child signing phase"
        );
        let (mut inner, vote) = self.inner.sign_first_vote_v10(producer)?;
        let prepared = inner
            .pending_epoch_commit
            .take()
            .context("successor signed child P missing")?;
        self.prepared.push(prepared);
        self.inner = inner;
        Ok((self, vote))
    }

    pub fn observe_front_qc_v11(
        self,
        certificate: trnm_consensus_types::QuorumCertificate,
    ) -> Result<Self> {
        ensure!(self.seals.is_empty() && self.prepared.len() == 3,
            "successor finality requires three actual P rows");
        let third = self.prepared[2].prepared.header()?;
        self.observe_application_front_qc_v11(certificate, third)
    }

    fn observe_application_front_qc_v11(
        mut self,
        certificate: trnm_consensus_types::QuorumCertificate,
        third: trnm_consensus_types::BlockHeader,
    ) -> Result<Self> {
        ensure!(!self.finality_observed && (1..=3).contains(&self.prepared.len()),
            "successor application front phase");
        ensure!(certificate.block_id() == third.id(), "successor QC names another block");
        let effects = self
            .inner
            .runtime
            .driver
            .step_v2(Input::QuorumCertificate(certificate))
            .map_err(|e| anyhow::anyhow!("successor finality QC: {e:?}"))?;
        let released = self.persist_ordinary_effects_v11(&effects)?;
        let first = self.prepared[0].prepared.header()?;
        let mut finalize = None;
        for effect in released {
            match effect {
                Effect::Finalize(value) if finalize.is_none() => finalize = Some(value),
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("successor QC released unexpected effect"),
            }
        }
        let finalize = finalize.context("successor Core emitted no Finalize")?;
        ensure!(
            finalize.proof().finalized_block().header() == &first
                && self.inner.runtime.driver.state().pending_finalization()
                    == Some(finalize.as_ref()),
            "successor Core queue-front changed"
        );
        self.inner.confirm_active_cut_v10()?;
        self.finality_observed = true;
        Ok(self)
    }

    /// Commit Core's exact queue front, then feed the independently read back
    /// native result back into Core and persist the resulting Safety transition.
    pub fn apply_front_v11(
        self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        self.confirm_ordinary_apply_phase_v11()?;
        self.apply_application_front_v11(budget)
    }

    fn confirm_ordinary_apply_phase_v11(&self) -> Result<()> {
        ensure!(self.seals.is_empty() && self.prepared.len() == 3, "successor apply phase");
        Ok(())
    }

    fn apply_application_front_v11(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        ensure!(self.finality_observed && (1..=3).contains(&self.prepared.len()),
            "successor apply phase");
        self.inner.confirm_active_cut_v10()?;
        let header = self.prepared[0].prepared.header()?;
        if header.block_kind() == BlockKind::EpochCheckpoint {
            self.confirm_pre_handoff_phase_v11()?;
        } else {
            ensure!(matches!(header.block_kind(), BlockKind::Regular | BlockKind::EpochHandoff),
                "successor application front is not executable");
        }
        let first = self.prepared.remove(0);
        let before = self
            .inner
            .application()
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        ensure!(before.commit_sequence().is_none(), "successor front already committed");
        let permit = self
            .inner
            .runtime
            .driver
            .issue_application_finalization_permit_v2()
            .map_err(|e| anyhow::anyhow!("successor apply permit: {e:?}"))?;
        ensure!(
            self.apply_authority
                .matches_application_finalization_permit_v0(&permit)
                && permit.finalization().proof().finalized_block().header() == &header
                && permit.finalization().target_overlay_ref().overlay_checksum()
                    == before.overlay_checksum(),
            "successor apply permit/native P mismatch"
        );
        let mut sources = self
            .inner
            .runtime
            .driver
            .state()
            .payload_validation_completions()
            .iter()
            .filter(|source| {
                source.id().block_id() == header.id()
                    && source.result().artifact_ref().is_some_and(|artifact| {
                        artifact.overlay().overlay_checksum() == before.overlay_checksum()
                            && artifact.source_artifact_checksum() == before.artifact_checksum()
                    })
            });
        let source = sources
            .next()
            .context("successor apply lacks exact Core Valid completion")?;
        let route = source.route();
        let id = source.id();
        let accepted_source = native_valid_result_checksum_v0(source.result())
            .context("successor apply source is not Valid")?;
        ensure!(sources.next().is_none(), "successor apply has ambiguous Valid provenance");
        let finalization_checksum =
            trnm_consensus_core::native_finalization_applied_checksum_v0(permit.finalization())
                .map_err(|e| anyhow::anyhow!("successor finalization checksum: {e:?}"))?;
        let proof_bytes = permit
            .finalization()
            .proof()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("successor finality bytes: {e:?}"))?;
        let prior = self.inner.application().confirmed_committed_head_v0()?;
        ensure!(
            &prior == first.prepared.application_parent(),
            "successor apply parent changed"
        );
        let selection = if header.block_kind() == BlockKind::EpochCheckpoint {
            self.checkpoint_selection.as_deref()
        } else {
            None
        };
        let committed = commit_application_front_v5(
            self.inner.application(),
            self.inner.runtime.driver.config(),
            &first.prepared,
            permit.finalization().proof(),
            &proof_bytes,
            selection,
            budget,
        )?;
        let current = committed.head.clone();
        let old = self.inner.runtime.checkpoint.fields().application;
        let next = EpochApplicationCutV1 {
            block_id: *current.block_id().as_bytes(),
            height: current.height().get(),
            epoch: first.epoch,
            view: first.view,
            timestamp_ms: first.timestamp_ms,
            state_root: *current.state_root().as_bytes(),
            native_store_id: old.native_store_id,
            native_commit_id: *current.commit_id().as_bytes(),
            p_sequence: first.prepared.persist_sequence(),
            p_digest: committed.p_digest,
            artifact_digest: first.prepared.artifact_digest(),
            overlay_digest: first.overlay_digest,
            commit_sequence: committed.sequence,
        };
        let ordinary = self.inner.ordinary_cut_v10()?;
        self.inner.advance_checkpoint_v10(
            self.inner.runtime.checkpoint.fields().target_safety,
            ordinary,
            next,
        )?;
        let fresh = self
            .inner
            .application()
            .confirm_prepared_epoch_execution_v1(&first.prepared)?;
        ensure!(
            fresh.commit_sequence() == Some(committed.sequence)
                && fresh.prepared().p_digest() == committed.p_digest
                && fresh.artifact_checksum() == before.artifact_checksum()
                && fresh.overlay_checksum() == before.overlay_checksum()
                && self.inner.application().confirmed_committed_head_v0()? == current,
            "successor committed P/readback mismatch"
        );
        let config = self.inner.application().config_v0();
        let host = epoch_transition_digest(
            "apply-v11-owner",
            &[
                config.chain_id_v0().as_bytes(),
                &config.genesis_hash_v0(),
                &config.store_id(),
                &config.chain_descriptor_hash_v0(),
                &self.inner.edge().successor_binding(),
            ],
        );
        let prior_digest = successor_application_head_digest_v11(&prior);
        let new_digest = successor_application_head_digest_v11(&current);
        let applied_job = epoch_transition_digest(
            "apply-v11-committed-p",
            &[
                &fresh.prepared().p_digest(),
                &fresh.prepared().persist_sequence().to_be_bytes(),
                &committed.sequence.to_be_bytes(),
                &fresh.artifact_checksum(),
                &fresh.overlay_checksum(),
                &new_digest,
            ],
        );
        let receipt_digest = epoch_transition_digest(
            "apply-v11-readback",
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
        let readback = self.apply_authority.application_store_apply_readback_v0(
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
        .map_err(|e| anyhow::anyhow!("successor application readback: {e:?}"))?;
        let receipt = self
            .apply_authority
            .receipt_after_application_store_apply_v0(permit, readback)
            .map_err(|e| anyhow::anyhow!("successor application receipt: {:?}", e.into_parts().0))?;
        let effects = self
            .inner
            .runtime
            .driver
            .step_application_finalization_receipt_v2(receipt)
            .map_err(|e| anyhow::anyhow!("successor Core applied receipt: {:?}", e.into_parts().0))?;
        let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
            anyhow::bail!("successor apply did not create one Safety barrier")
        };
        let manifest = request
            .native_finalization_applied_v0()
            .context("successor apply lacks typed Core manifest")?;
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
        let safety = self.inner.runtime.journal.persist_exact_v4(
            self.inner.runtime.pin,
            request,
            &context,
        )?;
        self.inner.runtime.pin = safety.pin_v4();
        self.inner.runtime.journal.confirm_exact_request_v4(
            self.inner.runtime.pin,
            request,
            &context,
        )?;
        let ordinary = self.inner.ordinary_cut_v10()?;
        let application = self.inner.runtime.checkpoint.fields().application;
        self.inner
            .advance_checkpoint_v10(safety_cut_v9(&safety), ordinary, application)?;
        self.inner.runtime.journal.confirm_exact_request_v4(
            self.inner.runtime.pin,
            request,
            &context,
        )?;
        let released = self
            .inner
            .runtime
            .driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier(),
            })
            .map_err(|e| anyhow::anyhow!("successor application ACK: {e:?}"))?;
        ensure!(
            released
                .iter()
                .all(|effect| matches!(effect, Effect::ArmViewTimer { .. })),
            "successor application ACK released unexpected authority"
        );
        ensure!(
            self.inner.runtime.driver.state().application_applied()
                == self.inner.runtime.driver.state().finalized()
                && self.inner.runtime.driver.state().pending_finalize().is_none()
                && self.inner.runtime.driver.state().pending_sign().is_none(),
            "successor Core application did not settle"
        );
        self.inner.confirm_active_cut_v10()?;
        self.finality_observed = false;
        self.pre_handoff = committed.pre_handoff;
        Ok(self)
    }

    fn verify_next_seal_v11(
        &mut self,
        proposal: &SignedProposalV0,
    ) -> Result<(trnm_consensus_types::QuorumCertificate, trnm_consensus_types::BlockHeader)> {
        ensure!(!self.inner.runtime.fenced, "successor seal owner fenced");
        ensure!(!self.finality_observed && self.seals.len() < 2
            && self.signed_seals == self.seals.len()
            && self.prepared.len() == 3 - self.seals.len()
            && self.inner.pending_epoch_commit.is_none(), "successor seal proposal phase");
        let selection = self.checkpoint_selection.as_ref().context("successor cutoff selection missing")?;
        let checkpoint = self.prepared.last().context("successor checkpoint P missing")?.prepared.header()?;
        ensure!(checkpoint.block_kind() == BlockKind::EpochCheckpoint,
            "successor seal requires actual checkpoint P");
        let parent = self.seals.last().map(|p| p.block().header()).unwrap_or(&checkpoint);
        let expected_kind = if self.seals.is_empty() { BlockKind::EpochSeal1 } else { BlockKind::EpochSeal2 };
        ensure!(proposal.block().header().block_kind() == expected_kind, "successor seal order");
        let params = self.inner.runtime.driver.config().consensus_parameters();
        trnm_consensus_types::validate_empty_epoch_seal_v1(proposal, parent, params)
            .map_err(|e| anyhow::anyhow!("successor seal semantics: {e:?}"))?;
        self.inner.runtime.driver.state().epoch_state_v1().context("successor epoch missing")?
            .strict_context().map_err(|e| anyhow::anyhow!("successor seal context: {e:?}"))?
            .verify_proposal_v1(proposal, parent,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(params))
            .map_err(|e| anyhow::anyhow!("successor seal cryptography: {e:?}"))?;
        confirm_retained_selection_v5(self.inner.application(), selection)?;
        let qc = proposal.witness().justify_qc().as_ordinary()
            .context("successor seal requires original parent QC")?.clone();
        let parent = parent.clone();
        // Invalid seal shape/signature is rejected without expensive durable
        // readback. Valid input still crosses the full current-owner fence
        // before Core can observe its certificate or create any effect.
        self.inner.confirm_active_cut_v10()?;
        Ok((qc, parent))
    }

    /// Retain the exact empty seal and let its carried QC expose the preceding
    /// application front. No seal payload is executed and no key is used here.
    pub fn admit_seal_proposal_v11(mut self, proposal: SignedProposalV0) -> Result<Self> {
        let (qc, parent) = self.verify_next_seal_v11(&proposal)?;
        self = self.observe_application_front_qc_v11(qc, parent)?;
        self.seals.push(proposal);
        Ok(self)
    }

    pub fn apply_preceding_seal_front_v11(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        ensure!((1..=2).contains(&self.seals.len())
            && self.signed_seals + 1 == self.seals.len()
            && self.prepared.len() == 4 - self.seals.len(), "successor seal preceding apply phase");
        self = self.apply_application_front_v11(budget)?;
        let proposal = self.seals.last().context("successor retained seal missing")?.clone();
        let effects = self.inner.runtime.driver.step_v2(Input::Proposal(Box::new(proposal.clone())))
            .map_err(|e| anyhow::anyhow!("successor seal after application ACK: {e:?}"))?;
        let released = self.persist_ordinary_effects_v11(&effects)?;
        let mut signs = 0;
        for effect in released {
            match effect {
                Effect::RequestSignature { .. } => signs += 1,
                Effect::ArmViewTimer { .. } => {},
                _ => anyhow::bail!("successor seal released unexpected application authority"),
            }
        }
        ensure!(signs == 1 && self.inner.runtime.driver.state().pending_finalize().is_none(),
            "successor seal requires isolated Vote after durable application ACK");
        confirm_seal_vote_at_context_v5(self.inner.runtime.driver.state(),
            self.inner.runtime.driver.config(), self.inner.application(),
            SealVoteProvenanceV5 {
                proposal: &proposal,
                checkpoint: &self.prepared.last().context("successor checkpoint missing")?.prepared,
                selection: self.checkpoint_selection.as_ref().context("successor selection missing")?,
            })?;
        self.inner.confirm_active_cut_v10()?;
        Ok(self)
    }

    pub fn sign_seal_vote_v11<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        ensure!(!self.finality_observed && (1..=2).contains(&self.seals.len())
            && self.signed_seals + 1 == self.seals.len()
            && self.prepared.len() == 3 - self.seals.len(), "successor seal Vote phase");
        let provenance = SealVoteProvenanceV5 {
            proposal: self.seals.last().context("successor seal missing")?,
            checkpoint: &self.prepared.last().context("successor checkpoint missing")?.prepared,
            selection: self.checkpoint_selection.as_ref().context("successor selection missing")?,
        };
        let (inner, vote) = self.inner.finish_pending_vote_v11(producer, Some(provenance))?;
        self.inner = inner;
        self.signed_seals += 1;
        Ok((self, vote))
    }

    /// Expose Core's exact next-checkpoint finality without granting native
    /// checkpoint commit, retirement or a new handoff/signing generation.
    pub fn observe_checkpoint_finality_v11(
        mut self,
        certificate: trnm_consensus_types::QuorumCertificate,
    ) -> Result<Self> {
        ensure!(self.signed_seals == 2 && self.seals.len() == 2
            && self.prepared.len() == 1, "successor terminal QC phase");
        let terminal = self.seals[1].block().header().clone();
        self = self.observe_application_front_qc_v11(certificate, terminal)?;
        let pending = self.inner.runtime.driver.state().pending_finalization()
            .context("successor checkpoint finality missing")?;
        ensure!(pending.proof().finalized_block().header() == &self.prepared[0].prepared.header()?
            && pending.proof().child().header() == self.seals[0].block().header()
            && pending.proof().grandchild().header() == self.seals[1].block().header(),
            "successor checkpoint original proof changed");
        Ok(self)
    }

    fn confirm_pre_handoff_phase_v11(&self) -> Result<()> {
        ensure!(self.finality_observed && self.prepared.len() == 1
            && self.seals.len() == 2 && self.signed_seals == 2
            && self.pre_handoff.is_none() && self.checkpoint_selection.is_some()
            && self.inner.pending_epoch_commit.is_none()
            && self.inner.pending_validation.is_none()
            && self.inner.runtime.driver.state().pending_sign().is_none(),
            "successor pre-handoff commit phase");
        let checkpoint = self.prepared[0].prepared.header()?;
        let pending = self.inner.runtime.driver.state().pending_finalization()
            .context("successor pre-handoff Core front missing")?;
        ensure!(checkpoint.block_kind() == BlockKind::EpochCheckpoint
            && pending.proof().finalized_block().header() == &checkpoint
            && pending.proof().child().header() == self.seals[0].block().header()
            && pending.proof().grandchild().header() == self.seals[1].block().header(),
            "successor pre-handoff original proof changed");
        Ok(())
    }

    /// Commit the original next checkpoint through the existing native13 owner.
    /// This does not retire the old ordinary signer or commission a new role.
    pub fn apply_pre_handoff_checkpoint_v11(
        self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        self.confirm_pre_handoff_phase_v11()?;
        let mut next = self.apply_application_front_v11(budget)?;
        next.settled_pre_handoff_cut_v11()?;
        Ok(next)
    }

    /// Fresh comparison of real owners, not retirement/new-generation authority.
    pub fn settled_pre_handoff_cut_v11(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(!self.finality_observed && self.prepared.is_empty()
            && self.pre_handoff.is_some() && self.seals.len() == 2
            && self.signed_seals == 2, "successor pre-handoff is not applied");
        let result = (|| {
            let checkpoint = self.inner.confirm_active_cut_v10()?;
            let receipt = self.pre_handoff.as_ref().context("successor pre-handoff receipt missing")?;
            let selection = self.checkpoint_selection.as_ref().context("successor cutoff missing")?;
            let state = self.inner.runtime.driver.state();
            ensure!(state.finalized() == state.application_applied()
                && state.application_applied().block_id().as_bytes() == &checkpoint.fields().application.block_id
                && state.pending_sign().is_none() && state.pending_finalize().is_none()
                && state.finalization_queue().is_empty() && state.payload_validation_obligations().is_empty()
                && state.old_epoch_boundary_v1().is_some_and(|b| b.phase(state)
                    == trnm_consensus_core::OldEpochBoundaryPhaseV1::CheckpointApplied),
                "successor pre-handoff Core/Safety not settled");
            ensure!(receipt.belongs_to_application(self.inner.application())
                && receipt.head().block_id().as_bytes() == &checkpoint.fields().application.block_id
                && receipt.commit_sequence() == checkpoint.fields().application.commit_sequence,
                "successor pre-handoff native receipt changed");
            let context = receipt.strict_context();
            let proof = state.last_finalization_proof().context("successor original finality missing")?;
            ensure!(context.old_validator_set() == self.inner.runtime.driver.config().validator_set()
                && context.old_consensus_parameters() == self.inner.runtime.driver.config().consensus_parameters()
                && context.new_validator_set() == selection.new_validator_set()
                && context.new_consensus_parameters() == selection.new_parameters()
                && context.next_epoch_commitment_digest() == selection.next_epoch_commitment().id()
                && context.checkpoint_finality_proof_id() == proof.id()
                && proof.finalized_block().header() == receipt.header()
                && proof.child().header() == self.seals[0].block().header()
                && proof.grandchild().header() == self.seals[1].block().header(),
                "successor pre-handoff original configuration/proof changed");
            // The planning API correctly refuses a committed checkpoint. Verify
            // the original retained cutoff, not a newly planned selection.
            let cutoff = self.inner.application().reopen_prepared_epoch_execution_v1(
                *selection.cutoff_head().block_id().as_bytes())?;
            let cutoff = self.inner.application().confirm_prepared_epoch_execution_v1(&cutoff)?;
            ensure!(cutoff.prepared().overlay_parent_head()? == *selection.cutoff_head()
                && cutoff.prepared().p_digest() == selection.cutoff_p_digest()
                && cutoff.prepared().persist_sequence() == selection.cutoff_p_sequence()
                && cutoff.commit_sequence() == Some(selection.cutoff_commit_sequence()),
                "successor pre-handoff retained cutoff changed");
            self.inner.confirm_active_cut_v10()
        })();
        if result.is_err() {
            self.inner.runtime.fenced = true;
        }
        result
    }

    pub fn settled_checkpoint_v11(&mut self) -> Result<EpochNodeCheckpointV1> {
        ensure!(
            !self.finality_observed
                && self.seals.is_empty()
                && self.prepared.len() == 2
                && self.inner.runtime.driver.state().application_applied()
                    == self.inner.runtime.driver.state().finalized(),
            "successor continuation is not settled"
        );
        self.inner.confirm_active_cut_v10()
    }

    #[cfg(test)]
    fn prepared_headers_v11(&self) -> Result<Vec<trnm_consensus_types::BlockHeader>> {
        self.prepared
            .iter()
            .map(|p| p.prepared.header())
            .collect()
    }

    #[cfg(test)]
    fn application_v11(&self) -> &DurableNativeApplicationV0 {
        self.inner.application()
    }

    #[cfg(test)]
    fn set_v11(&self) -> &trnm_consensus_types::ValidatorSet {
        self.inner.runtime.driver.config().validator_set()
    }

    #[cfg(test)]
    fn parameters_v11(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        self.inner.runtime.driver.config().consensus_parameters()
    }
}

fn successor_application_head_digest_v11(
    head: &trnm_native_application::ApplicationHeadV0,
) -> [u8; 32] {
    epoch_transition_digest(
        "apply-v11-head",
        &[
            &head.height().get().to_be_bytes(),
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ],
    )
}
