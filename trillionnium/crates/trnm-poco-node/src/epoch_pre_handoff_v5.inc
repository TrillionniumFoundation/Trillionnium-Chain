type AppliedEpochFrontV5<W, N> = (
    FirstEpochFinalizationRuntimeV2<W, N>,
    Option<Box<trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1>>,
);

#[derive(Clone, Copy)]
struct SealVoteProvenanceV5<'a> {
    proposal: &'a SignedProposalV0,
    checkpoint: &'a PreparedNativeEpochExecutionV1,
    selection: &'a trnm_native_execution_v0::ComputedLaterEpochSelectionV1,
}

// No public constructor can select a different source of signing authority.
enum EpochKeyProvenanceV5<'a> {
    Application(&'a PreparedNativeEpochExecutionV1),
    Seal(SealVoteProvenanceV5<'a>),
    Timeout,
}

fn confirm_retained_selection_v5(
    application: &DurableNativeApplicationV0,
    expected: &trnm_native_execution_v0::ComputedLaterEpochSelectionV1,
) -> Result<()> {
    let fresh = application.compute_later_epoch_selection_v1(expected.cutoff_head().height())?;
    ensure!(
        fresh.cutoff_head() == expected.cutoff_head()
            && fresh.cutoff_p_digest() == expected.cutoff_p_digest()
            && fresh.cutoff_p_sequence() == expected.cutoff_p_sequence()
            && fresh.cutoff_commit_sequence() == expected.cutoff_commit_sequence()
            && fresh.next_epoch_commitment() == expected.next_epoch_commitment()
            && fresh.new_validator_set() == expected.new_validator_set()
            && fresh.new_parameters() == expected.new_parameters(),
        "retained cutoff selection changed"
    );
    Ok(())
}

fn confirm_seal_vote_provenance_v5(
    driver: &PendingEpochHostDriverV1,
    application: &DurableNativeApplicationV0,
    edge: &AuthenticatedEpochApplicationEdgeV1,
    source: SealVoteProvenanceV5<'_>,
) -> Result<()> {
    ensure!(
        driver.config().validator_set() == edge.new_validator_set()
            && driver.config().consensus_parameters() == edge.new_parameters(),
        "seal active edge changed"
    );
    confirm_seal_vote_at_context_v5(driver.state(), driver.config(), application, source)
}

fn confirm_seal_vote_at_context_v5(
    state: &trnm_consensus_core::SafetyState,
    config: &trnm_consensus_core::CoreConfig,
    application: &DurableNativeApplicationV0,
    source: SealVoteProvenanceV5<'_>,
) -> Result<()> {
    let header = source.proposal.block().header();
    ensure!(
        matches!(state.pending_sign(), Some(SignIntent::Vote { block_id, height, view, .. })
        if *block_id == header.id() && *height == header.height() && *view == header.view()),
        "seal key boundary differs from the actual pending Vote"
    );
    let boundary = state
        .old_epoch_boundary_v1()
        .context("seal lacks outgoing boundary")?;
    ensure!(
        boundary
            .seals()
            .iter()
            .filter(|p| *p == source.proposal)
            .count()
            == 1,
        "seal key boundary lacks exact retained SignedProposal"
    );
    let parent = boundary
        .checkpoints()
        .iter()
        .map(|p| p.proposal())
        .chain(boundary.seals().iter())
        .find(|p| p.block().id() == header.parent_id())
        .context("seal retained parent missing")?;
    ensure!(
        header.validator_set_id() == config.validator_set().id()
            && header.consensus_parameters_hash() == config.consensus_parameters().hash()
            && header.epoch() == config.validator_set().epoch()
            && state.payload_terminal_fact(header.id()).is_none()
            && !state
                .payload_validation_completions()
                .iter()
                .any(|p| p.id().block_id() == header.id())
            && !state
                .payload_validation_obligations()
                .iter()
                .any(|p| p.proposal().block().id() == header.id()),
        "seal acquired application provenance or changed active configuration"
    );
    trnm_consensus_types::validate_empty_epoch_seal_v1(
        source.proposal,
        parent.block().header(),
        config.consensus_parameters(),
    )
    .map_err(|e| anyhow::anyhow!("seal key boundary semantics: {e:?}"))?;
    state
        .epoch_state_v1()
        .context("seal active epoch missing")?
        .strict_context()
        .map_err(|e| anyhow::anyhow!("seal strict context: {e:?}"))?
        .verify_proposal_v1(
            source.proposal,
            parent.block().header(),
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(config.consensus_parameters()),
        )
        .map_err(|e| anyhow::anyhow!("seal key boundary cryptography: {e:?}"))?;
    let checkpoint = application.confirm_prepared_epoch_execution_v1(source.checkpoint)?;
    let ch = checkpoint.prepared().header()?;
    ensure!(
        checkpoint.commit_sequence().is_none()
            && ch.block_kind() == BlockKind::EpochCheckpoint
            && ch.next_epoch_commitment_hash()
                == Some(source.selection.next_epoch_commitment().id())
            && header.next_epoch_commitment_hash() == ch.next_epoch_commitment_hash()
            && header.state_root() == ch.state_root(),
        "seal checkpoint P changed"
    );
    let cp = boundary
        .checkpoints()
        .iter()
        .find(|p| p.proposal().block().header() == &ch)
        .context("seal checkpoint lacks Core-retained proposal")?;
    let (payload, _) = checkpoint.application_payload_and_receipts()?;
    ensure!(
        payload
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("checkpoint body: {e:?}"))?
            == cp.proposal().block().application_payload(),
        "seal checkpoint original body changed"
    );
    ensure!(
        state
            .payload_validation_completions()
            .iter()
            .filter(|p| {
                p.id().block_id() == ch.id()
                    && p.result().artifact_ref().is_some_and(|a| {
                        a.source_artifact_checksum() == checkpoint.artifact_checksum()
                            && a.overlay().block_id() == ch.id()
                            && a.overlay().parent_block_id() == ch.parent_id()
                            && a.overlay().overlay_checksum() == checkpoint.overlay_checksum()
                    })
            })
            .count()
            == 1,
        "seal checkpoint lacks exact durable Core Valid"
    );
    confirm_retained_selection_v5(application, source.selection)
}

/// The same live owner through two seal Votes and an unattached native
/// pre-handoff checkpoint. No role signature, retirement or recovery is exposed.
#[must_use]
pub struct EpochPreHandoffRuntimeV5<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
{
    inner: Option<Box<FirstEpochFinalizationRuntimeV2<W, N>>>,
    selection: Box<trnm_native_execution_v0::ComputedLaterEpochSelectionV1>,
    seals: Vec<SignedProposalV0>,
    signed_seals: usize,
    receipt: Option<Box<trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1>>,
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    EpochCheckpointPreparationRuntimeV4<W, N>
{
    pub fn into_pre_handoff_v5(mut self) -> Result<EpochPreHandoffRuntimeV5<W, N>> {
        self.prepared_checkpoint_cut_v4()?;
        let inner = self.inner.take().context("checkpoint owner fenced")?;
        let header = inner
            .prepared
            .last()
            .context("checkpoint P missing")?
            .prepared
            .header()?;
        confirm_checkpoint_selection_v4(
            &inner.runtime.application,
            &inner.runtime.edge,
            &inner.runtime.checkpoint,
            &header,
        )?;
        let geometry = trnm_consensus_types::EpochGeometryV0::new(
            header.epoch(),
            inner.runtime.edge.new_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("seal geometry: {e:?}"))?;
        let cutoff = geometry
            .checkpoint_height()
            .get()
            .checked_sub(inner.runtime.edge.new_parameters().snapshot_lead_blocks())
            .context("seal cutoff underflow")?;
        let selection =
            Box::new(inner.runtime.application.compute_later_epoch_selection_v1(
                trnm_native_application::HeightV0::new(cutoff),
            )?);
        Ok(EpochPreHandoffRuntimeV5 {
            inner: Some(inner),
            selection,
            seals: Vec::new(),
            signed_seals: 0,
            receipt: None,
        })
    }
}

impl<W: ExternalSignerRetirementV1, N: ExternalMonotonicWatermarkV0>
    EpochPreHandoffRuntimeV5<W, N>
{
    /// Authenticates the original seal and processes its carried QC. The seal
    /// itself stays inert until the preceding application has been acknowledged.
    pub fn admit_seal_proposal_v5(&mut self, proposal: SignedProposalV0) -> Result<()> {
        let inner = self.inner.as_mut().context("pre-handoff owner fenced")?;
        ensure!(
            self.receipt.is_none()
                && self.seals.len() < 2
                && self.signed_seals == self.seals.len()
                && inner.prepared.len() == 3 - self.seals.len(),
            "seal proposal phase"
        );
        inner.require_collecting()?;
        let checkpoint = &inner
            .prepared
            .last()
            .context("seal checkpoint P missing")?
            .prepared;
        let cp_header = checkpoint.header()?;
        let parent = self
            .seals
            .last()
            .map(|p| p.block().header())
            .unwrap_or(&cp_header);
        let expected_kind = if self.seals.is_empty() {
            BlockKind::EpochSeal1
        } else {
            BlockKind::EpochSeal2
        };
        ensure!(
            proposal.block().header().block_kind() == expected_kind,
            "seal proposal order"
        );
        trnm_consensus_types::validate_empty_epoch_seal_v1(
            &proposal,
            parent,
            inner.runtime.edge.new_parameters(),
        )
        .map_err(|e| anyhow::anyhow!("seal proposal semantics: {e:?}"))?;
        inner
            .runtime
            .driver
            .state()
            .epoch_state_v1()
            .context("seal epoch missing")?
            .strict_context()
            .map_err(|e| anyhow::anyhow!("seal context: {e:?}"))?
            .verify_proposal_v1(
                &proposal,
                parent,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_parameters(
                    inner.runtime.edge.new_parameters(),
                ),
            )
            .map_err(|e| anyhow::anyhow!("seal proposal cryptography: {e:?}"))?;
        confirm_retained_selection_v5(&inner.runtime.application, &self.selection)?;
        let certificate = proposal
            .witness()
            .justify_qc()
            .as_ordinary()
            .context("seal requires its parent's original ordinary QC")?
            .clone();
        let mut inner = self.inner.take().context("pre-handoff owner missing")?;
        // Core forbids simultaneous signing/finalization outboxes. Settle the
        // exact application front authenticated by this QC before admitting
        // the original seal proposal, which remains inert private input here.
        let effects = inner
            .runtime
            .driver
            .step_v1(Input::QuorumCertificate(certificate))
            .map_err(|e| anyhow::anyhow!("seal carried Core QC: {e:?}"))?;
        let released = inner.persist_ordinary_effects(&effects)?;
        let mut finalize = None;
        for effect in released {
            match effect {
                Effect::Finalize(value) if finalize.is_none() => finalize = Some(value),
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("seal proposal released unexpected authority"),
            }
        }
        let finalize =
            finalize.context("seal did not produce its actual preceding application front")?;
        let front = inner
            .prepared
            .first()
            .context("seal application front missing")?
            .prepared
            .header()?;
        ensure!(
            inner.runtime.driver.state().pending_sign().is_none()
                && finalize.proof().finalized_block().header() == &front
                && inner.runtime.driver.state().pending_finalization() == Some(finalize.as_ref()),
            "seal Core queue front or Vote mismatch"
        );
        inner.finality_observed = true;
        self.seals.push(proposal);
        self.inner = Some(inner);
        Ok(())
    }

    pub fn sign_seal_vote_v5<P: trnm_consensus_signer_journal::SignatureProducerV0>(
        mut self,
        producer: &mut P,
    ) -> Result<(Self, trnm_consensus_core::OutboundMessage)> {
        ensure!(
            self.receipt.is_none() && self.seals.len() == self.signed_seals + 1,
            "seal Vote phase"
        );
        let mut inner = self.inner.take().context("pre-handoff owner fenced")?;
        ensure!(
            inner.prepared.len() == 3 - self.seals.len()
                && !inner.finality_observed
                && !inner.applied,
            "seal Vote waits for application ACK"
        );
        inner.runtime.confirm_current_cut_v1()?;
        let source = SealVoteProvenanceV5 {
            proposal: self.seals.last().context("seal missing")?,
            checkpoint: &inner
                .prepared
                .last()
                .context("seal checkpoint P missing")?
                .prepared,
            selection: &self.selection,
        };
        let (runtime, vote) = (*inner.runtime).finish_pending_vote_v5(producer, Some(source))?;
        inner.runtime = Box::new(runtime);
        self.signed_seals += 1;
        self.inner = Some(inner);
        Ok((self, vote))
    }

    /// Applies the genuine preceding front, then persists the original seal
    /// proposal so its isolated Vote obligation can cross the signing boundary.
    pub fn apply_preceding_application_v5(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        ensure!(
            self.receipt.is_none()
                && self.signed_seals + 1 == self.seals.len()
                && (1..=2).contains(&self.seals.len()),
            "seal preceding application phase"
        );
        let inner = self.inner.take().context("pre-handoff owner fenced")?;
        ensure!(
            inner.prepared.len() == 4 - self.seals.len()
                && inner
                    .prepared
                    .first()
                    .context("application front missing")?
                    .prepared
                    .header()?
                    .block_kind()
                    == BlockKind::Regular,
            "seal preceding application front"
        );
        let (mut inner, receipt) = (*inner).apply_front_v5(budget, None)?;
        ensure!(
            receipt.is_none(),
            "ordinary application minted pre-handoff receipt"
        );
        inner.prepared.remove(0);
        inner.finality_observed = false;
        inner.applied = false;
        let proposal = self.seals.last().context("pending original seal missing")?;
        let effects = inner
            .runtime
            .driver
            .step_v1(Input::Proposal(Box::new(proposal.clone())))
            .map_err(|e| anyhow::anyhow!("seal Core proposal after application ACK: {e:?}"))?;
        let released = inner.persist_ordinary_effects(&effects)?;
        let mut signs = 0;
        for effect in released {
            match effect {
                Effect::RequestSignature { .. } => signs += 1,
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("settled seal proposal released unexpected authority"),
            }
        }
        ensure!(
            signs == 1 && inner.runtime.driver.state().pending_finalize().is_none(),
            "seal proposal lacks isolated Vote obligation"
        );
        confirm_seal_vote_provenance_v5(
            &inner.runtime.driver,
            &inner.runtime.application,
            &inner.runtime.edge,
            SealVoteProvenanceV5 {
                proposal,
                checkpoint: &inner
                    .prepared
                    .last()
                    .context("checkpoint P missing")?
                    .prepared,
                selection: &self.selection,
            },
        )?;
        self.inner = Some(Box::new(inner));
        Ok(self)
    }

    pub fn observe_terminal_qc_v5(
        &mut self,
        certificate: trnm_consensus_types::QuorumCertificate,
    ) -> Result<()> {
        ensure!(
            self.receipt.is_none() && self.signed_seals == 2 && self.seals.len() == 2,
            "terminal QC phase"
        );
        let inner = self.inner.as_mut().context("pre-handoff owner fenced")?;
        inner.require_collecting()?;
        ensure!(
            inner.prepared.len() == 1 && certificate.block_id() == self.seals[1].block().id(),
            "terminal QC target"
        );
        let mut inner = self.inner.take().context("pre-handoff owner missing")?;
        let effects = inner
            .runtime
            .driver
            .step_v1(Input::QuorumCertificate(certificate))
            .map_err(|e| anyhow::anyhow!("terminal Core QC: {e:?}"))?;
        let released = inner.persist_ordinary_effects(&effects)?;
        let mut front = None;
        for effect in released {
            match effect {
                Effect::Finalize(value) if front.is_none() => front = Some(value),
                Effect::ArmViewTimer { .. } => {}
                _ => anyhow::bail!("terminal QC released unexpected authority"),
            }
        }
        let front = front.context("terminal QC lacks checkpoint front")?;
        let proof = front.proof();
        ensure!(
            proof.finalized_block().header() == &inner.prepared[0].prepared.header()?
                && proof.child().header() == self.seals[0].block().header()
                && proof.grandchild().header() == self.seals[1].block().header()
                && inner.runtime.driver.state().pending_finalization() == Some(front.as_ref()),
            "terminal QC original finality substitution"
        );
        inner.finality_observed = true;
        self.inner = Some(inner);
        Ok(())
    }

    pub fn apply_pre_handoff_checkpoint_v5(
        mut self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<Self> {
        ensure!(
            self.receipt.is_none() && self.signed_seals == 2,
            "pre-handoff application phase"
        );
        let mut inner = self.inner.take().context("pre-handoff owner fenced")?;
        ensure!(
            inner.prepared.len() == 1 && inner.finality_observed,
            "pre-handoff checkpoint front missing"
        );
        inner.runtime.confirm_current_cut_v1()?;
        confirm_retained_selection_v5(&inner.runtime.application, &self.selection)?;
        let current = inner.runtime.application.confirmed_committed_head_v0()?;
        inner
            .runtime
            .application
            .upgrade_later_epoch_schema_v1(&current)?;
        inner.runtime.confirm_current_cut_v1()?;
        inner
            .runtime
            .application
            .upgrade_later_epoch_pre_handoff_schema_v1(&current)?;
        inner.runtime.confirm_current_cut_v1()?;
        let (inner, receipt) = (*inner).apply_front_v5(budget, Some(&self.selection))?;
        self.receipt = Some(receipt.context("native pre-handoff receipt missing")?);
        self.inner = Some(Box::new(inner));
        self.settled_pre_handoff_cut_v5()?;
        Ok(self)
    }

    /// An inert owner comparison; no retirement or handoff authority is released.
    pub fn settled_pre_handoff_cut_v5(&mut self) -> Result<EpochNodeCheckpointV1> {
        let receipt = self.receipt.as_ref().context("pre-handoff not applied")?;
        let inner = self.inner.as_mut().context("pre-handoff owner fenced")?;
        let checkpoint = inner.settled_checkpoint_v2()?;
        ensure!(
            receipt.belongs_to_application(&inner.runtime.application)
                && receipt.head().block_id().as_bytes()
                    == &checkpoint.fields().application.block_id
                && receipt.commit_sequence() == checkpoint.fields().application.commit_sequence
                && inner.runtime.driver.state().pending_sign().is_none()
                && inner
                    .runtime
                    .driver
                    .state()
                    .payload_validation_obligations()
                    .is_empty(),
            "pre-handoff settlement changed"
        );
        Ok(checkpoint)
    }
}

struct CommittedApplicationFrontV5 {
    head: trnm_native_application::ApplicationHeadV0,
    sequence: u64,
    p_digest: [u8; 32],
    pre_handoff: Option<Box<trnm_native_execution_v0::CommittedLaterEpochPreHandoffV1>>,
}

#[inline(never)]
fn commit_application_front_v5(
    application: &DurableNativeApplicationV0,
    config: &trnm_consensus_core::CoreConfig,
    prepared: &PreparedNativeEpochExecutionV1,
    proof: &trnm_consensus_types::FinalityProofV0,
    proof_bytes: &[u8],
    selection: Option<&trnm_native_execution_v0::ComputedLaterEpochSelectionV1>,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<CommittedApplicationFrontV5> {
    let Some(selection) = selection else {
        let committed =
            application.commit_epoch_finality_bytes_v1(prepared, proof_bytes, budget)?;
        ensure!(
            committed.belongs_to_application(application),
            "committed application owner changed"
        );
        return Ok(CommittedApplicationFrontV5 {
            head: committed.head().clone(),
            sequence: committed.commit_sequence(),
            p_digest: committed.p_digest(),
            pre_handoff: None,
        });
    };
    confirm_retained_selection_v5(application, selection)?;
    let checkpoint = proof.finalized_block().header();
    let terminal = proof.grandchild().header();
    let old_set = config.validator_set();
    let new_set = selection.new_validator_set();
    ensure!(
        checkpoint == &prepared.header()?
            && checkpoint.block_kind() == BlockKind::EpochCheckpoint
            && proof.child().header().block_kind() == BlockKind::EpochSeal1
            && terminal.block_kind() == BlockKind::EpochSeal2
            && checkpoint.next_epoch_commitment_hash()
                == Some(selection.next_epoch_commitment().id()),
        "pre-handoff original Core proof geometry"
    );
    let descriptor = trnm_consensus_types::HandoffDescriptorV0::new(
        trnm_consensus_types::HandoffDescriptorV0Fields {
            genesis_hash: old_set.genesis_hash(),
            chain_id: old_set.chain_id(),
            old_epoch: old_set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: old_set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: old_set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: config.consensus_parameters().hash(),
            new_consensus_parameters_hash: selection.new_parameters().hash(),
            checkpoint_height: checkpoint.height(),
            checkpoint_block_id: checkpoint.id(),
            checkpoint_state_root: checkpoint.state_root(),
            next_epoch_commitment_digest: selection.next_epoch_commitment().id(),
            terminal_old_height: terminal.height(),
            terminal_old_block_id: terminal.id(),
            terminal_old_qc_digest: proof.grandchild().certifying_qc().id(),
            terminal_old_view: terminal.view(),
            activation_height: terminal
                .height()
                .checked_next()
                .map_err(|e| anyhow::anyhow!("activation height: {e:?}"))?,
            initial_new_view: trnm_consensus_types::View::new(1),
        },
    )
    .map_err(|e| anyhow::anyhow!("local pre-handoff descriptor: {e:?}"))?;
    let commitment_bytes = selection
        .next_epoch_commitment()
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("commitment bytes: {e:?}"))?;
    let set_bytes = new_set
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("new set bytes: {e:?}"))?;
    let parameters = selection.new_parameters().canonical_bytes();
    let committed = Box::new(application.commit_later_epoch_pre_handoff_v1(
        prepared,
        proof_bytes,
        &descriptor,
        &commitment_bytes,
        &set_bytes,
        &parameters,
        budget,
    )?);
    ensure!(
        committed.belongs_to_application(application)
            && committed.header() == checkpoint
            && committed.strict_context().descriptor() == &descriptor
            && committed.strict_context().checkpoint_finality_proof_id() == proof.id(),
        "pre-handoff native receipt differs from original Core proof"
    );
    Ok(CommittedApplicationFrontV5 {
        head: committed.head().clone(),
        sequence: committed.commit_sequence(),
        p_digest: prepared.p_digest(),
        pre_handoff: Some(committed),
    })
}
