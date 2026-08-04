use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};

use trnm_consensus_types::{
    Epoch, EquivocationEvidence, Proposal, ProposalJustification, QcRef, QuorumCertificate,
    SignatureVerifier, TimeoutCertificate, TimeoutVote, ValidatorId, ValidatorSet, View, Vote,
};

use crate::{
    block_tree::{Ancestry, BlockTree},
    model::{DeferredEffect, PendingPersistence},
    BarrierId, CoreConfig, CoreError, Effect, FinalizedTip, Input, OutboundMessage, Result,
    SafetyState, SignIntent, ValidationId,
};

type ObservationKey = (Epoch, View, ValidatorId);

/// A deterministic, single-threaded PoCO-BFT state machine.
///
/// `Core` owns no clock, network, database, or private key. All interaction
/// with those facilities is represented by [`Input`] and [`Effect`]. Failed
/// steps are transactional: no state is changed when `step` returns an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Core {
    config: CoreConfig,
    safety: SafetyState,
    blocks: BlockTree,
    pending_validations: BTreeMap<ValidationId, Proposal>,
    pending_sync_validations: BTreeMap<ValidationId, Proposal>,
    pending_persistence: Option<PendingPersistence>,
    awaiting_signature: bool,
    observed_proposals: BTreeMap<ObservationKey, Proposal>,
    observed_votes: BTreeMap<ObservationKey, Vote>,
    observed_timeouts: BTreeMap<ObservationKey, TimeoutVote>,
    observed_qcs: BTreeMap<View, QuorumCertificate>,
    next_validation_generation: u64,
    replay_required: bool,
}

impl Core {
    /// Starts a core from a verified bootstrap certificate.
    pub fn new<V: SignatureVerifier>(
        config: CoreConfig,
        genesis_qc: QuorumCertificate,
        verifier: &V,
    ) -> Result<Self> {
        config.validate()?;
        if config.validator_set().epoch().get() != 0 {
            return Err(CoreError::InvalidConfig(
                "a new core must start in genesis epoch zero",
            ));
        }
        genesis_qc.verify(config.validator_set(), verifier)?;
        if genesis_qc.view().get() != 0 || genesis_qc.height().get() != 0 {
            return Err(CoreError::InvalidConfig(
                "genesis QC must certify protocol view and height zero",
            ));
        }
        if genesis_qc.block_id() != config.genesis_block_id() {
            return Err(CoreError::InvalidConfig(
                "genesis QC does not certify the configured genesis block",
            ));
        }
        let safety = SafetyState::from_genesis(config.validator_set(), genesis_qc)?;
        let value = Self::empty(config, safety, false);
        value.validate_runtime(verifier)?;
        Ok(value)
    }

    /// Restores the durable safety state after a process restart.
    ///
    /// If `state.pending_sign()` is present, the caller must feed `Resume` and
    /// the core will request precisely that already-persisted signing root.
    /// The volatile block tree is rebuilt by replaying verified proposals and
    /// certificates from the finalized tip through the durable high QC; stale
    /// replay inputs never cause a vote.
    ///
    /// The storage/signer integration must reject a snapshot whose revision
    /// or signing watermarks precede its append-only sign journal. A
    /// self-consistent `SafetyState` cannot prove it is the newest durable
    /// record in isolation.
    pub fn recover<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<Self> {
        config.validate()?;
        let replay_required = safety_replay_required(&state);
        let value = Self::empty(config, state, replay_required);
        value.validate_runtime(verifier)?;
        Ok(value)
    }

    pub const fn config(&self) -> &CoreConfig {
        &self.config
    }

    pub const fn safety_state(&self) -> &SafetyState {
        &self.safety
    }

    pub fn pending_validation_count(&self) -> usize {
        self.pending_validations.len() + self.pending_sync_validations.len()
    }

    /// Applies one deterministic input and returns ordered effects.
    pub fn step<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let previous_safety = self.safety.clone();
        let mut next = self.clone();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier)?;
        next.validate_monotonic_transition(&previous_safety)?;
        *self = next;
        Ok(effects)
    }

    fn empty(config: CoreConfig, safety: SafetyState, replay_required: bool) -> Self {
        let max_blocks = config.max_blocks();
        // Every validation request is released only after a safety-state
        // persistence barrier. Seeding the volatile counter from the durable
        // revision keeps delayed pre-restart validation results from matching
        // a newly issued request.
        let next_validation_generation = safety.revision();
        let mut observed_qcs = BTreeMap::new();
        observed_qcs.insert(safety.locked_qc().view(), safety.locked_qc().clone());
        match observed_qcs.get(&safety.high_qc().view()) {
            Some(existing)
                if existing.block_id() == safety.high_qc().block_id()
                    && existing.id() >= safety.high_qc().id() => {}
            _ => {
                observed_qcs.insert(safety.high_qc().view(), safety.high_qc().clone());
            }
        }
        Self {
            config,
            safety,
            blocks: BlockTree::new(max_blocks),
            pending_validations: BTreeMap::new(),
            pending_sync_validations: BTreeMap::new(),
            pending_persistence: None,
            awaiting_signature: false,
            observed_proposals: BTreeMap::new(),
            observed_votes: BTreeMap::new(),
            observed_timeouts: BTreeMap::new(),
            observed_qcs,
            next_validation_generation,
            replay_required,
        }
    }

    fn apply<V: SignatureVerifier>(&mut self, input: Input, verifier: &V) -> Result<Vec<Effect>> {
        self.reject_while_busy(&input)?;
        match input {
            Input::Resume => self.resume(),
            Input::Proposal(proposal) => self.handle_proposal(*proposal, verifier),
            Input::Vote(vote) => self.handle_vote(vote, verifier),
            Input::TimeoutVote(vote) => self.handle_timeout_vote(vote, verifier),
            Input::QuorumCertificate(certificate) => self.handle_qc(certificate, verifier),
            Input::TimeoutCertificate(certificate) => self.handle_tc(certificate, verifier),
            Input::LocalTimeout { epoch, view } => self.handle_local_timeout(epoch, view),
            Input::PayloadValidated { id, valid } => self.handle_payload_validated(id, valid),
            Input::SyncedPayloadValidated { id, valid } => {
                self.handle_synced_payload_validated(id, valid)
            }
            Input::StorageAck { barrier } => self.handle_storage_ack(barrier),
            Input::FinalizationApplied { proof_id } => self.handle_finalization_applied(proof_id),
            Input::SafetyReplayComplete => self.handle_replay_complete(),
            Input::SignatureReady { id, signature } => {
                self.handle_signature(id, signature, verifier)
            }
        }
    }

    fn reject_while_busy(&self, input: &Input) -> Result<()> {
        if self.pending_persistence.is_some() && !matches!(input, Input::StorageAck { .. }) {
            return Err(CoreError::Busy(
                "waiting for durable safety-state acknowledgement",
            ));
        }
        if self.safety.safety_halt().is_some()
            && !matches!(input, Input::Resume | Input::StorageAck { .. })
        {
            return Err(CoreError::Busy(
                "consensus is safety-halted pending operator recovery",
            ));
        }
        if self.awaiting_signature && !matches!(input, Input::SignatureReady { .. } | Input::Resume)
        {
            return Err(CoreError::Busy("waiting for the requested signature"));
        }
        if self.safety.pending_sign().is_some()
            && !self.awaiting_signature
            && self.pending_persistence.is_none()
            && !matches!(input, Input::Resume)
        {
            return Err(CoreError::Busy("persisted signing intent must be resumed"));
        }
        if self.safety.pending_finalize().is_some()
            && !matches!(
                input,
                Input::Resume | Input::StorageAck { .. } | Input::FinalizationApplied { .. }
            )
        {
            return Err(CoreError::Busy(
                "waiting for application finalization acknowledgement",
            ));
        }
        if self.replay_required && matches!(input, Input::LocalTimeout { .. }) {
            return Err(CoreError::Busy(
                "safety ancestry replay must complete before a new signing intent",
            ));
        }
        Ok(())
    }

    fn resume(&mut self) -> Result<Vec<Effect>> {
        if let Some(halt) = self.safety.safety_halt().cloned() {
            return Ok(vec![Effect::SafetyHalted(Box::new(halt))]);
        }
        if let Some(intent) = self.safety.pending_sign().cloned() {
            self.awaiting_signature = true;
            return Ok(vec![self.signature_effect(&intent)]);
        }
        if let Some(proof) = self.safety.pending_finalize().cloned() {
            return Ok(vec![Effect::Finalize(Box::new(proof))]);
        }
        let mut effects = Vec::new();
        if self.replay_required {
            effects.push(Effect::RequestSafetyReplay {
                finalized: self.safety.finalized(),
                high_qc: QcRef::from(self.safety.high_qc()),
                locked_qc: QcRef::from(self.safety.locked_qc()),
            });
        }
        effects.push(Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        });
        Ok(effects)
    }

    fn handle_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: Proposal,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if proposal.block().payload().len() > self.config.max_block_bytes() {
            return Err(CoreError::BlockTooLarge {
                actual: proposal.block().payload().len(),
                maximum: self.config.max_block_bytes(),
            });
        }
        proposal.verify(self.config.validator_set(), verifier)?;
        let header = proposal.block().header();
        self.require_epoch(header.epoch())?;
        if let ProposalJustification::Quorum(certificate) = proposal.justification() {
            let expected_view = certificate.view().checked_next()?;
            if header.view() != expected_view {
                return Err(CoreError::WrongView {
                    expected: expected_view,
                    received: header.view(),
                });
            }
        }
        let expected = leader_for(self.config.validator_set(), header.view());
        if proposal.proposer() != expected {
            return Err(CoreError::UnexpectedLeader {
                expected: Box::new(expected),
                received: Box::new(proposal.proposer()),
            });
        }

        let mut side_effects = Vec::new();
        if let Some(evidence) = self.observe_proposal(&proposal)? {
            side_effects.push(Effect::Evidence(evidence));
        }
        self.observe_proposal_justification(&proposal, &mut side_effects)?;
        let proposal_qc = proposal_high_qc(&proposal);
        for referenced_qc in proposal_referenced_qcs(&proposal) {
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                self.safety.set_safety_halt(Some(halt));
                let mut effects = self.persist(vec![DeferredEffect::SafetyHalted])?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }

        let live_candidate = header.view() >= self.safety.current_view()
            && header.height() > self.safety.finalized().height();
        let replay_candidate = self.replay_required
            && header.view() < self.safety.current_view()
            && header.height() > self.safety.finalized().height()
            && header.height().get() <= self.replay_max_height();
        if live_candidate || replay_candidate {
            match self.blocks.validate_proposal_parent(
                header,
                proposal_qc,
                self.safety.finalized(),
                self.config.max_block_time_step_ms(),
            ) {
                Ancestry::Descends => {}
                Ancestry::Unknown => return Err(CoreError::MissingBlock(header.parent_id())),
                Ancestry::Conflicts => return Err(CoreError::UnsafeProposal),
            }
            self.blocks.attach_certificate(proposal_qc)?;
            let protected = self.protected_blocks();
            self.blocks.insert_header(
                proposal.block().header().clone(),
                Some(proposal_qc.clone()),
                &protected,
            )?;
        }

        if replay_candidate {
            if self.blocks.payload_is_known(proposal.block().id()) {
                return Ok(side_effects);
            }
            let (id, is_new) = self.register_sync_validation(&proposal)?;
            if is_new {
                let mut effects = self.persist(vec![DeferredEffect::ValidateSyncedPayload {
                    id,
                    block: Box::new(proposal.block().clone()),
                }])?;
                effects.extend(side_effects);
                return Ok(effects);
            }
            return Ok(side_effects);
        }

        if header.view() < self.safety.current_view()
            || header.height() <= self.safety.finalized().height()
        {
            return Ok(side_effects);
        }

        let before = self.safety.clone();
        self.learn_qc(proposal_qc.clone())?;
        if header.view() > self.safety.current_view() {
            self.safety.set_current_view(header.view());
        }

        let validation = if self.blocks.payload_is_known(proposal.block().id()) {
            None
        } else {
            Some(self.register_validation(&proposal)?)
        };

        let safety_changed = self.safety != before;
        if safety_changed || validation.is_some_and(|(_, is_new)| is_new) {
            let mut deferred = Vec::new();
            if safety_changed {
                deferred.push(DeferredEffect::ArmViewTimer);
            }
            if let Some((id, true)) = validation {
                deferred.push(DeferredEffect::ValidatePayload {
                    id,
                    block: Box::new(proposal.block().clone()),
                });
            }
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if let Some((id, true)) = validation {
            side_effects.push(Effect::ValidatePayload {
                id,
                block: proposal.block().clone(),
            });
        }
        Ok(side_effects)
    }

    fn handle_payload_validated(&mut self, id: ValidationId, valid: bool) -> Result<Vec<Effect>> {
        let proposal = self
            .pending_validations
            .remove(&id)
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        self.blocks
            .set_payload_validity(proposal.block().id(), valid)?;
        if !valid || proposal.block().header().view() != self.safety.current_view() {
            return Ok(Vec::new());
        }
        if self.replay_required {
            return Err(CoreError::Busy(
                "safety ancestry replay must complete before a new signing intent",
            ));
        }
        if self
            .safety
            .last_voted_view()
            .is_some_and(|view| view >= id.view())
        {
            return Ok(Vec::new());
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::ConcurrentSignIntent);
        }

        let justify = proposal_high_qc(&proposal);
        if justify.block_id() != self.safety.finalized().block_id()
            && !self.blocks.contains_header(justify.block_id())
        {
            // A QC proves votes for an identifier, not availability or the
            // certified parent's header. Never unlock/vote across that gap.
            return Ok(Vec::new());
        }
        match self.blocks.validated_ancestry(
            proposal.block().id(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            Ancestry::Unknown | Ancestry::Conflicts => return Ok(Vec::new()),
        }
        let extends_lock = self
            .blocks
            .extends(proposal.block().id(), self.safety.locked_qc().block_id());
        let unlocks = justify.view() > self.safety.locked_qc().view();
        if !extends_lock && !unlocks {
            return Ok(Vec::new());
        }

        let header = proposal.block().header();
        let root = Vote::signing_root_for_set(
            self.config.validator_set(),
            header.view(),
            header.height(),
            proposal.block().id(),
        )?;
        self.safety.set_last_voted(header.view());
        self.safety.set_pending_sign(Some(SignIntent::Vote {
            view: header.view(),
            height: header.height(),
            block_id: proposal.block().id(),
            signing_root: root,
        }));
        self.persist(vec![DeferredEffect::RequestSignature])
    }

    fn handle_synced_payload_validated(
        &mut self,
        id: ValidationId,
        valid: bool,
    ) -> Result<Vec<Effect>> {
        let proposal = self
            .pending_sync_validations
            .remove(&id)
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        self.blocks
            .set_payload_validity(proposal.block().id(), valid)?;
        Ok(Vec::new())
    }

    fn handle_local_timeout(&mut self, epoch: Epoch, view: View) -> Result<Vec<Effect>> {
        self.require_epoch(epoch)?;
        if view != self.safety.current_view() {
            return Err(CoreError::WrongView {
                expected: self.safety.current_view(),
                received: view,
            });
        }
        if self
            .safety
            .last_timeout_view()
            .is_some_and(|last| last >= view)
        {
            return Ok(Vec::new());
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::ConcurrentSignIntent);
        }
        let high_qc = QcRef::from(self.safety.high_qc());
        let root = TimeoutVote::signing_root_for_set(self.config.validator_set(), view, high_qc)?;
        self.safety.set_last_timeout(view);
        self.safety.set_pending_sign(Some(SignIntent::TimeoutVote {
            view,
            high_qc,
            signing_root: root,
        }));
        self.persist(vec![DeferredEffect::RequestSignature])
    }

    fn handle_storage_ack(&mut self, barrier: BarrierId) -> Result<Vec<Effect>> {
        let pending = self
            .pending_persistence
            .take()
            .ok_or(CoreError::UnexpectedStorageAck)?;
        if pending.barrier != barrier {
            return Err(CoreError::UnexpectedStorageAck);
        }
        let mut effects = Vec::with_capacity(pending.deferred.len());
        for effect in pending.deferred {
            match effect {
                DeferredEffect::RequestSignature => {
                    let intent = self
                        .safety
                        .pending_sign()
                        .cloned()
                        .ok_or(CoreError::UnexpectedSignature)?;
                    self.awaiting_signature = true;
                    effects.push(self.signature_effect(&intent));
                }
                DeferredEffect::ArmViewTimer => effects.push(Effect::ArmViewTimer {
                    epoch: self.safety.epoch(),
                    view: self.safety.current_view(),
                }),
                DeferredEffect::ValidatePayload { id, block } => {
                    effects.push(Effect::ValidatePayload { id, block: *block });
                }
                DeferredEffect::ValidateSyncedPayload { id, block } => {
                    effects.push(Effect::ValidateSyncedPayload { id, block: *block });
                }
                DeferredEffect::SafetyHalted => {
                    let halt = self
                        .safety
                        .safety_halt()
                        .cloned()
                        .ok_or(CoreError::ConflictingCertificate)?;
                    effects.push(Effect::SafetyHalted(Box::new(halt)));
                }
                DeferredEffect::Finalize(proof) => effects.push(Effect::Finalize(proof)),
            }
        }
        Ok(effects)
    }

    fn handle_finalization_applied(
        &mut self,
        proof_id: trnm_consensus_types::CertificateId,
    ) -> Result<Vec<Effect>> {
        let proof = self
            .safety
            .pending_finalize()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if proof.id() != proof_id {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        self.safety.set_pending_finalize(None);
        self.persist(Vec::new())
    }

    fn handle_replay_complete(&mut self) -> Result<Vec<Effect>> {
        if self.replay_required {
            let mut anchors = vec![self.safety.high_qc().block_id()];
            if self.safety.locked_qc().block_id() != self.safety.finalized().block_id() {
                anchors.push(self.safety.locked_qc().block_id());
            }
            for certificate in [
                self.safety.high_qc().clone(),
                self.safety.locked_qc().clone(),
            ] {
                if certificate.block_id() != self.safety.finalized().block_id() {
                    self.blocks.attach_certificate(&certificate)?;
                }
            }
            for block_id in anchors {
                if block_id == self.safety.finalized().block_id() {
                    continue;
                }
                match self.blocks.validated_ancestry(
                    block_id,
                    self.safety.finalized(),
                    self.config.max_block_time_step_ms(),
                ) {
                    Ancestry::Descends => {}
                    Ancestry::Conflicts => {
                        return Err(CoreError::InvalidRecovery(
                            "replayed safety anchor conflicts with finalized tip",
                        ));
                    }
                    Ancestry::Unknown => {
                        return Err(CoreError::InvalidRecovery(
                            "replayed ancestry does not reach every safety anchor",
                        ));
                    }
                }
            }
        }
        self.replay_required = false;
        Ok(vec![Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        }])
    }

    fn handle_signature<V: SignatureVerifier>(
        &mut self,
        id: crate::SignId,
        signature: trnm_consensus_types::SignatureBytes,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if !self.awaiting_signature {
            return Err(CoreError::UnexpectedSignature);
        }
        let intent = self
            .safety
            .pending_sign()
            .cloned()
            .ok_or(CoreError::UnexpectedSignature)?;
        if intent.id() != id {
            return Err(CoreError::SignIdMismatch);
        }
        let outbound = match intent {
            SignIntent::Vote {
                view,
                height,
                block_id,
                signing_root,
            } => {
                if signing_root != id.signing_root() {
                    return Err(CoreError::SignIdMismatch);
                }
                let vote = Vote::new(
                    self.safety.chain_id(),
                    self.safety.protocol_version(),
                    self.safety.epoch(),
                    view,
                    height,
                    block_id,
                    self.safety.validator_set_id(),
                    self.config.local_validator(),
                    signature,
                    self.config.validator_set(),
                )?;
                vote.verify(self.config.validator_set(), verifier)?;
                OutboundMessage::Vote(vote)
            }
            SignIntent::TimeoutVote {
                view,
                high_qc,
                signing_root,
            } => {
                if signing_root != id.signing_root() {
                    return Err(CoreError::SignIdMismatch);
                }
                let vote = TimeoutVote::new(
                    self.safety.chain_id(),
                    self.safety.protocol_version(),
                    self.safety.epoch(),
                    view,
                    self.safety.validator_set_id(),
                    high_qc,
                    self.config.local_validator(),
                    signature,
                    self.config.validator_set(),
                )?;
                vote.verify(self.config.validator_set(), verifier)?;
                OutboundMessage::TimeoutVote(vote)
            }
        };
        self.awaiting_signature = false;
        self.safety.set_pending_sign(None);
        Ok(vec![Effect::Broadcast(outbound)])
    }

    fn handle_vote<V: SignatureVerifier>(
        &mut self,
        vote: Vote,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        vote.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(vote.epoch())?;
        Ok(self
            .observe_vote(&vote)?
            .map(|evidence| vec![Effect::Evidence(evidence)])
            .unwrap_or_default())
    }

    fn handle_timeout_vote<V: SignatureVerifier>(
        &mut self,
        vote: TimeoutVote,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        vote.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(vote.epoch())?;
        Ok(self
            .observe_timeout(&vote)?
            .map(|evidence| vec![Effect::Evidence(evidence)])
            .unwrap_or_default())
    }

    fn handle_qc<V: SignatureVerifier>(
        &mut self,
        certificate: QuorumCertificate,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        certificate.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(certificate.epoch())?;
        let mut side_effects = Vec::new();
        for vote in certificate.votes() {
            if let Some(evidence) = self.observe_vote(vote)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }
        if let Some(halt) = self.observe_qc(&certificate)? {
            self.safety.set_safety_halt(Some(halt));
            let mut effects = self.persist(vec![DeferredEffect::SafetyHalted])?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if self.blocks.payload_is_invalid(certificate.block_id()) {
            return Err(CoreError::ConflictingCertificate);
        }
        self.blocks.attach_certificate(&certificate)?;

        let before = self.safety.clone();
        self.learn_qc(certificate.clone())?;
        let next_view = certificate.view().checked_next()?;
        self.safety.set_current_view(next_view);

        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if let Some(proof) = self
            .blocks
            .detect_three_chain(&certificate, self.config.validator_set())?
        {
            proof.verify(self.config.validator_set(), verifier)?;
            let committed = proof.committed();
            if committed.height() > self.safety.finalized().height() {
                match self.blocks.validated_ancestry(
                    committed.id(),
                    self.safety.finalized(),
                    self.config.max_block_time_step_ms(),
                ) {
                    Ancestry::Descends => {
                        self.safety.set_finalized(FinalizedTip::new(
                            committed.height(),
                            committed.view(),
                            committed.id(),
                            committed.timestamp_ms(),
                        ));
                        self.blocks
                            .prune_below(committed.height().get(), committed.id());
                        self.safety.set_last_finalization_proof(proof.clone());
                        self.safety.set_pending_finalize(Some(proof.clone()));
                        deferred.push(DeferredEffect::Finalize(Box::new(proof)));
                    }
                    Ancestry::Conflicts => return Err(CoreError::ConflictingCertificate),
                    // Recovery deliberately starts with an empty volatile
                    // tree. Withhold finalization until stale verified
                    // proposals/QCs replay the missing ancestry.
                    Ancestry::Unknown => {}
                }
            }
        }

        if self.safety != before {
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            Ok(effects)
        } else {
            Ok(side_effects)
        }
    }

    fn handle_tc<V: SignatureVerifier>(
        &mut self,
        certificate: TimeoutCertificate,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        certificate.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(certificate.epoch())?;
        let mut side_effects = Vec::new();
        for referenced_qc in certificate.referenced_qcs() {
            for vote in referenced_qc.votes() {
                if let Some(evidence) = self.observe_vote(vote)? {
                    side_effects.push(Effect::Evidence(evidence));
                }
            }
        }
        for vote in certificate.timeout_votes() {
            if let Some(evidence) = self.observe_timeout(vote)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }

        for referenced_qc in certificate.referenced_qcs() {
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                self.safety.set_safety_halt(Some(halt));
                let mut effects = self.persist(vec![DeferredEffect::SafetyHalted])?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }

        self.blocks.attach_certificate(certificate.high_qc())?;
        let before = self.safety.clone();
        self.learn_qc(certificate.high_qc().clone())?;
        self.safety
            .set_current_view(certificate.view().checked_next()?);

        if self.safety != before {
            let mut effects = self.persist(vec![DeferredEffect::ArmViewTimer])?;
            effects.extend(side_effects);
            Ok(effects)
        } else {
            Ok(side_effects)
        }
    }

    fn observe_proposal_justification(
        &mut self,
        proposal: &Proposal,
        effects: &mut Vec<Effect>,
    ) -> Result<()> {
        match proposal.justification() {
            ProposalJustification::Quorum(certificate) => {
                for vote in certificate.votes() {
                    if let Some(evidence) = self.observe_vote(vote)? {
                        effects.push(Effect::Evidence(evidence));
                    }
                }
            }
            ProposalJustification::Timeout(certificate) => {
                for referenced_qc in certificate.referenced_qcs() {
                    for vote in referenced_qc.votes() {
                        if let Some(evidence) = self.observe_vote(vote)? {
                            effects.push(Effect::Evidence(evidence));
                        }
                    }
                }
                for vote in certificate.timeout_votes() {
                    if let Some(evidence) = self.observe_timeout(vote)? {
                        effects.push(Effect::Evidence(evidence));
                    }
                }
            }
        }
        Ok(())
    }

    fn register_validation(&mut self, proposal: &Proposal) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_validations, proposal) {
            return Ok((id, false));
        }
        if self.pending_validation_count() >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.pending_validations.insert(id, proposal.clone());
        Ok((id, true))
    }

    fn register_sync_validation(&mut self, proposal: &Proposal) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_sync_validations, proposal) {
            return Ok((id, false));
        }
        if self.pending_validation_count() >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.pending_sync_validations.insert(id, proposal.clone());
        Ok((id, true))
    }

    fn next_validation_id(&mut self, proposal: &Proposal) -> Result<ValidationId> {
        self.next_validation_generation = self
            .next_validation_generation
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow("validation generation"))?;
        Ok(ValidationId::new(
            proposal.block().id(),
            proposal.block().header().view(),
            self.next_validation_generation,
        ))
    }

    fn observe_proposal(&mut self, proposal: &Proposal) -> Result<Option<EquivocationEvidence>> {
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        if let Some(first) = self.observed_proposals.get(&key).cloned() {
            if first.conflicts_with(proposal) {
                return Ok(Some(EquivocationEvidence::proposal(
                    first,
                    proposal.clone(),
                    self.config.validator_set(),
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_proposals,
            key,
            proposal.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_vote(&mut self, vote: &Vote) -> Result<Option<EquivocationEvidence>> {
        let key = (vote.epoch(), vote.view(), vote.author());
        if let Some(first) = self.observed_votes.get(&key).cloned() {
            if first.conflicts_with(vote) {
                return Ok(Some(EquivocationEvidence::vote(
                    first,
                    vote.clone(),
                    self.config.validator_set(),
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_votes,
            key,
            vote.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_timeout(&mut self, vote: &TimeoutVote) -> Result<Option<EquivocationEvidence>> {
        let key = (vote.epoch(), vote.view(), vote.author());
        if let Some(first) = self.observed_timeouts.get(&key).cloned() {
            if first.conflicts_with(vote) {
                return Ok(Some(EquivocationEvidence::timeout(
                    first,
                    vote.clone(),
                    self.config.validator_set(),
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_timeouts,
            key,
            vote.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn observe_qc(&mut self, certificate: &QuorumCertificate) -> Result<Option<crate::SafetyHalt>> {
        for durable in self.durable_qcs() {
            if durable.view() == certificate.view() && durable.block_id() != certificate.block_id()
            {
                return Ok(Some(crate::SafetyHalt::from_conflicting_qcs(
                    durable.clone(),
                    certificate.clone(),
                )?));
            }
        }
        if let Some(first) = self.observed_qcs.get(&certificate.view()).cloned() {
            if first.block_id() != certificate.block_id() {
                return Ok(Some(crate::SafetyHalt::from_conflicting_qcs(
                    first,
                    certificate.clone(),
                )?));
            }
            if certificate.id() > first.id() {
                self.observed_qcs
                    .insert(certificate.view(), certificate.clone());
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_qcs,
            certificate.view(),
            certificate.clone(),
            self.config.max_observed_messages(),
        );
        Ok(None)
    }

    fn learn_qc(&mut self, certificate: QuorumCertificate) -> Result<()> {
        self.require_descendant_of_finalized(&certificate)?;
        if certificate.block_id() != self.safety.finalized().block_id() {
            if self.blocks.payload_is_invalid(certificate.block_id()) {
                return Err(CoreError::ConflictingCertificate);
            }
            if !self.blocks.payload_is_valid(certificate.block_id()) {
                return Err(CoreError::MissingBlock(certificate.block_id()));
            }
            let justify = self
                .blocks
                .justify_qc(certificate.block_id())
                .cloned()
                .ok_or(CoreError::MissingBlock(certificate.block_id()))?;
            if justify.view() > self.safety.locked_qc().view() {
                self.safety.set_locked_qc(justify);
            } else if justify.view() == self.safety.locked_qc().view()
                && justify.block_id() != self.safety.locked_qc().block_id()
            {
                return Err(CoreError::ConflictingCertificate);
            } else if justify.view() == self.safety.locked_qc().view()
                && justify.block_id() == self.safety.locked_qc().block_id()
                && justify.id() > self.safety.locked_qc().id()
            {
                self.safety.set_locked_qc(justify);
            }
        }
        self.adopt_high_qc(certificate)
    }

    fn adopt_high_qc(&mut self, certificate: QuorumCertificate) -> Result<()> {
        self.require_descendant_of_finalized(&certificate)?;
        let current = self.safety.high_qc();
        if certificate.view() == current.view() && certificate.block_id() != current.block_id() {
            return Err(CoreError::ConflictingCertificate);
        }
        if qc_order_key(&certificate) > qc_order_key(current) {
            self.safety.set_high_qc(certificate);
        }
        Ok(())
    }

    fn require_descendant_of_finalized(&self, certificate: &QuorumCertificate) -> Result<()> {
        let finalized = self.safety.finalized();
        if certificate.block_id() == finalized.block_id() {
            if certificate.height() == finalized.height() && certificate.view() == finalized.view()
            {
                return Ok(());
            }
            return Err(CoreError::ConflictingCertificate);
        }
        match self.blocks.validated_ancestry(
            certificate.block_id(),
            finalized,
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => Ok(()),
            Ancestry::Conflicts => Err(CoreError::ConflictingCertificate),
            Ancestry::Unknown => Err(CoreError::MissingBlock(certificate.block_id())),
        }
    }

    fn durable_qcs(&self) -> Vec<&QuorumCertificate> {
        let mut certificates = vec![self.safety.high_qc(), self.safety.locked_qc()];
        if let Some(proof) = self.safety.last_finalization_proof() {
            certificates.extend([
                proof.committed_qc(),
                proof.child_qc(),
                proof.grandchild_qc(),
            ]);
        }
        certificates
    }

    fn persist(&mut self, deferred: Vec<DeferredEffect>) -> Result<Vec<Effect>> {
        if self.pending_persistence.is_some() {
            return Err(CoreError::Busy("a safety-state write is already pending"));
        }
        let barrier = self.safety.next_revision()?;
        self.pending_persistence = Some(PendingPersistence { barrier, deferred });
        Ok(vec![Effect::PersistSafetyState {
            barrier,
            state: Box::new(self.safety.clone()),
        }])
    }

    fn signature_effect(&self, intent: &SignIntent) -> Effect {
        Effect::RequestSignature {
            id: intent.id(),
            author: self.config.local_validator(),
            kind: intent.kind(),
            signing_root: intent.signing_root(),
        }
    }

    fn protected_blocks(&self) -> Vec<trnm_consensus_types::BlockId> {
        let mut protected = vec![
            self.safety.high_qc().block_id(),
            self.safety.locked_qc().block_id(),
            self.safety.finalized().block_id(),
        ];
        protected.extend(
            self.pending_validations
                .keys()
                .map(|validation| validation.block_id()),
        );
        protected.extend(
            self.pending_sync_validations
                .keys()
                .map(|validation| validation.block_id()),
        );
        protected
    }

    fn replay_max_height(&self) -> u64 {
        core::cmp::max(
            self.safety.high_qc().height().get(),
            self.safety.locked_qc().height().get(),
        )
    }

    fn require_epoch(&self, epoch: Epoch) -> Result<()> {
        if epoch != self.safety.epoch() {
            return Err(CoreError::WrongEpoch {
                expected: self.safety.epoch(),
                received: epoch,
            });
        }
        Ok(())
    }

    fn validate_runtime<V: SignatureVerifier>(&self, verifier: &V) -> Result<()> {
        self.config.validate()?;
        let set = self.config.validator_set();
        if self.safety.chain_id() != set.chain_id() {
            return Err(CoreError::InvalidRecovery(
                "chain id does not match validator set",
            ));
        }
        if self.safety.protocol_version() != set.protocol_version() {
            return Err(CoreError::InvalidRecovery(
                "protocol version does not match validator set",
            ));
        }
        if self.safety.epoch() != set.epoch() {
            return Err(CoreError::InvalidRecovery(
                "epoch does not match validator set",
            ));
        }
        if self.safety.validator_set_id() != set.id() {
            return Err(CoreError::InvalidRecovery(
                "validator-set id does not match validator set",
            ));
        }
        if self.safety.genesis_block_id() != self.config.genesis_block_id() {
            return Err(CoreError::InvalidRecovery(
                "trusted genesis block does not match core configuration",
            ));
        }
        self.safety.high_qc().verify(set, verifier)?;
        self.safety.locked_qc().verify(set, verifier)?;
        match self.safety.last_finalization_proof() {
            Some(proof) => {
                proof.verify(set, verifier)?;
                if !proof_timestamps_valid(proof, self.config.max_block_time_step_ms()) {
                    return Err(CoreError::InvalidRecovery(
                        "last finalization proof violates the timestamp step bound",
                    ));
                }
                let committed = proof.committed();
                if committed.height() != self.safety.finalized().height()
                    || committed.view() != self.safety.finalized().view()
                    || committed.id() != self.safety.finalized().block_id()
                    || committed.timestamp_ms() != self.safety.finalized().timestamp_ms()
                {
                    return Err(CoreError::InvalidRecovery(
                        "last finalization proof does not bind the finalized tip",
                    ));
                }
            }
            None => {
                if self.safety.finalized().height().get() != 0
                    || self.safety.finalized().view().get() != 0
                    || self.safety.finalized().block_id() != self.safety.genesis_block_id()
                    || self.safety.finalized().timestamp_ms() != 0
                {
                    return Err(CoreError::InvalidRecovery(
                        "a non-genesis finalized tip requires a permanent proof",
                    ));
                }
            }
        }
        let durable_qcs = self.durable_qcs();
        for (index, first) in durable_qcs.iter().enumerate() {
            for second in durable_qcs.iter().skip(index + 1) {
                if first.view() == second.view() && first.block_id() != second.block_id() {
                    return Err(CoreError::InvalidRecovery(
                        "durable state contains conflicting QCs at one view",
                    ));
                }
            }
        }
        if let Some(proof) = self.safety.last_finalization_proof() {
            if qc_order_key(self.safety.high_qc()) < qc_order_key(proof.grandchild_qc()) {
                return Err(CoreError::InvalidRecovery(
                    "high QC is behind the permanent finalization proof",
                ));
            }
            if qc_order_key(self.safety.locked_qc()) < qc_order_key(proof.child_qc()) {
                return Err(CoreError::InvalidRecovery(
                    "locked QC is behind the permanent finalization proof",
                ));
            }
        }
        if self.safety.locked_qc().view() > self.safety.high_qc().view() {
            return Err(CoreError::InvalidRecovery("locked QC is ahead of high QC"));
        }
        if self.safety.locked_qc().height() < self.safety.finalized().height() {
            return Err(CoreError::InvalidRecovery(
                "locked QC is behind the finalized tip",
            ));
        }
        if self.safety.locked_qc().height() == self.safety.finalized().height()
            && self.safety.locked_qc().block_id() != self.safety.finalized().block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "equal-height locked QC conflicts with finalized tip",
            ));
        }
        if self.safety.locked_qc().view() == self.safety.high_qc().view()
            && self.safety.locked_qc().block_id() != self.safety.high_qc().block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "equal-view locked and high QCs certify different blocks",
            ));
        }
        if self.safety.locked_qc().view() == self.safety.high_qc().view()
            && self.safety.locked_qc().block_id() == self.safety.high_qc().block_id()
            && self.safety.locked_qc().id() > self.safety.high_qc().id()
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC digest is ordered above the high QC",
            ));
        }
        for certificate in [self.safety.high_qc(), self.safety.locked_qc()] {
            if certificate.block_id() == self.safety.finalized().block_id()
                && (certificate.height() != self.safety.finalized().height()
                    || certificate.view() != self.safety.finalized().view())
            {
                return Err(CoreError::InvalidRecovery(
                    "QC coordinates do not match the finalized anchor",
                ));
            }
        }
        if self.safety.current_view() <= self.safety.high_qc().view() {
            return Err(CoreError::InvalidRecovery(
                "current view must be ahead of the high QC",
            ));
        }
        if self.safety.finalized().height() > self.safety.high_qc().height() {
            return Err(CoreError::InvalidRecovery(
                "finalized height is ahead of the high QC",
            ));
        }
        if self.safety.finalized().view() > self.safety.high_qc().view() {
            return Err(CoreError::InvalidRecovery(
                "finalized view is ahead of the high QC",
            ));
        }
        if self.safety.finalized().height() == self.safety.high_qc().height()
            && self.safety.finalized().block_id() != self.safety.high_qc().block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "equal-height finalized tip and high QC identify different blocks",
            ));
        }
        if self
            .safety
            .last_voted_view()
            .is_some_and(|view| view > self.safety.current_view())
        {
            return Err(CoreError::InvalidRecovery(
                "last voted view is in the future",
            ));
        }
        if self
            .safety
            .last_timeout_view()
            .is_some_and(|view| view > self.safety.current_view())
        {
            return Err(CoreError::InvalidRecovery(
                "last timeout view is in the future",
            ));
        }
        if self.awaiting_signature && self.safety.pending_sign().is_none() {
            return Err(CoreError::InvalidRecovery(
                "signature request has no durable signing intent",
            ));
        }
        if self.safety.pending_sign().is_some() && self.safety.pending_finalize().is_some() {
            return Err(CoreError::InvalidRecovery(
                "signing and finalization outboxes cannot both be active",
            ));
        }
        if let Some(intent) = self.safety.pending_sign() {
            if intent.view() != self.safety.current_view() {
                return Err(CoreError::InvalidRecovery(
                    "pending signing intent is not for the current view",
                ));
            }
            let expected = match intent {
                SignIntent::Vote {
                    view,
                    height,
                    block_id,
                    ..
                } => {
                    if self.safety.last_voted_view() != Some(*view) {
                        return Err(CoreError::InvalidRecovery(
                            "vote intent does not match last voted view",
                        ));
                    }
                    Vote::signing_root_for_set(set, *view, *height, *block_id)?
                }
                SignIntent::TimeoutVote { view, high_qc, .. } => {
                    if self.safety.last_timeout_view() != Some(*view) {
                        return Err(CoreError::InvalidRecovery(
                            "timeout intent does not match last timeout view",
                        ));
                    }
                    if *high_qc != QcRef::from(self.safety.high_qc()) {
                        return Err(CoreError::InvalidRecovery(
                            "timeout intent does not reference the durable high QC",
                        ));
                    }
                    TimeoutVote::signing_root_for_set(set, *view, *high_qc)?
                }
            };
            if expected != intent.signing_root() {
                return Err(CoreError::InvalidRecovery(
                    "persisted signing root is incorrect",
                ));
            }
        }
        if let Some(proof) = self.safety.pending_finalize() {
            proof.verify(set, verifier)?;
            if self.safety.last_finalization_proof() != Some(proof) {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox is not the permanent finalization proof",
                ));
            }
            if proof.committed().height() != self.safety.finalized().height()
                || proof.committed().view() != self.safety.finalized().view()
                || proof.committed().id() != self.safety.finalized().block_id()
            {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox does not match finalized tip",
                ));
            }
        }
        if let Some(halt) = self.safety.safety_halt() {
            halt.first().verify(set, verifier)?;
            halt.second().verify(set, verifier)?;
            let canonical = crate::SafetyHalt::from_conflicting_qcs(
                halt.first().clone(),
                halt.second().clone(),
            )?;
            if &canonical != halt {
                return Err(CoreError::InvalidRecovery(
                    "safety-halt QC pair is not canonically encoded",
                ));
            }
            if self.safety.pending_sign().is_some() || self.safety.pending_finalize().is_some() {
                return Err(CoreError::InvalidRecovery(
                    "safety-halted state contains an active outbox",
                ));
            }
        }
        Ok(())
    }

    fn validate_monotonic_transition(&self, previous: &SafetyState) -> Result<()> {
        if self.safety.current_view() < previous.current_view() {
            return Err(CoreError::InvalidRecovery("current view regressed"));
        }
        if option_regressed(previous.last_voted_view(), self.safety.last_voted_view()) {
            return Err(CoreError::InvalidRecovery("last voted view regressed"));
        }
        if option_regressed(
            previous.last_timeout_view(),
            self.safety.last_timeout_view(),
        ) {
            return Err(CoreError::InvalidRecovery("last timeout view regressed"));
        }
        if self.safety.high_qc().view() < previous.high_qc().view() {
            return Err(CoreError::InvalidRecovery("high QC regressed"));
        }
        if self.safety.high_qc().view() == previous.high_qc().view()
            && self.safety.high_qc().block_id() != previous.high_qc().block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "high QC changed block at the same view",
            ));
        }
        if self.safety.high_qc().view() == previous.high_qc().view()
            && self.safety.high_qc().block_id() == previous.high_qc().block_id()
            && self.safety.high_qc().id() < previous.high_qc().id()
        {
            return Err(CoreError::InvalidRecovery("high QC digest regressed"));
        }
        if self.safety.locked_qc().view() < previous.locked_qc().view() {
            return Err(CoreError::InvalidRecovery("locked QC regressed"));
        }
        if self.safety.locked_qc().view() == previous.locked_qc().view()
            && self.safety.locked_qc().block_id() != previous.locked_qc().block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC changed block at the same view",
            ));
        }
        if self.safety.locked_qc().view() == previous.locked_qc().view()
            && self.safety.locked_qc().block_id() == previous.locked_qc().block_id()
            && self.safety.locked_qc().id() < previous.locked_qc().id()
        {
            return Err(CoreError::InvalidRecovery("locked QC digest regressed"));
        }
        if self.safety.finalized().height() < previous.finalized().height()
            || self.safety.finalized().view() < previous.finalized().view()
        {
            return Err(CoreError::InvalidRecovery("finalized tip regressed"));
        }
        if self.safety.finalized().height() == previous.finalized().height()
            && self.safety.finalized() != previous.finalized()
        {
            return Err(CoreError::InvalidRecovery(
                "finalized tip changed at the same height",
            ));
        }
        if self.safety.finalized() == previous.finalized()
            && self.safety.last_finalization_proof() != previous.last_finalization_proof()
        {
            return Err(CoreError::InvalidRecovery(
                "permanent finalization proof changed without advancing finality",
            ));
        }
        if self.safety.revision() < previous.revision()
            || self.safety.revision().saturating_sub(previous.revision()) > 1
        {
            return Err(CoreError::InvalidRecovery(
                "safety-state revision is not monotonic",
            ));
        }
        if previous.safety_halt().is_some() && self.safety.safety_halt() != previous.safety_halt() {
            return Err(CoreError::InvalidRecovery(
                "safety halt was cleared or changed",
            ));
        }
        Ok(())
    }
}

/// Selects leaders by round-robin over the validator set's canonical order.
pub fn leader_for(validator_set: &ValidatorSet, view: View) -> ValidatorId {
    let validators = validator_set.validators();
    debug_assert!(!validators.is_empty());
    let index = (view.get().saturating_sub(1) % validators.len() as u64) as usize;
    validators[index].id()
}

fn proposal_high_qc(proposal: &Proposal) -> &QuorumCertificate {
    match proposal.justification() {
        ProposalJustification::Quorum(certificate) => certificate,
        ProposalJustification::Timeout(certificate) => certificate.high_qc(),
    }
}

fn proposal_referenced_qcs(proposal: &Proposal) -> Vec<&QuorumCertificate> {
    match proposal.justification() {
        ProposalJustification::Quorum(certificate) => vec![certificate],
        ProposalJustification::Timeout(certificate) => {
            certificate.referenced_qcs().iter().collect()
        }
    }
}

fn safety_replay_required(state: &SafetyState) -> bool {
    state.high_qc().block_id() != state.finalized().block_id()
        || state.locked_qc().block_id() != state.finalized().block_id()
}

fn qc_order_key(
    certificate: &QuorumCertificate,
) -> (
    View,
    trnm_consensus_types::BlockId,
    trnm_consensus_types::CertificateId,
) {
    (certificate.view(), certificate.block_id(), certificate.id())
}

fn pending_validation_id(
    pending: &BTreeMap<ValidationId, Proposal>,
    proposal: &Proposal,
) -> Option<ValidationId> {
    pending
        .iter()
        .find(|(id, _)| {
            id.block_id() == proposal.block().id() && id.view() == proposal.block().header().view()
        })
        .map(|(id, _)| *id)
}

fn proof_timestamps_valid(proof: &trnm_consensus_types::CommitProof, maximum_step_ms: u64) -> bool {
    timestamp_edge_valid(
        proof.committed().timestamp_ms(),
        proof.child().timestamp_ms(),
        maximum_step_ms,
    ) && timestamp_edge_valid(
        proof.child().timestamp_ms(),
        proof.grandchild().timestamp_ms(),
        maximum_step_ms,
    )
}

fn timestamp_edge_valid(parent_ms: u64, child_ms: u64, maximum_step_ms: u64) -> bool {
    parent_ms
        .checked_add(maximum_step_ms)
        .is_some_and(|maximum| child_ms > parent_ms && child_ms <= maximum)
}

fn bounded_insert<K: Ord + Copy, V>(map: &mut BTreeMap<K, V>, key: K, value: V, maximum: usize) {
    if map.len() >= maximum && !map.contains_key(&key) {
        if let Some(oldest) = map.keys().next().copied() {
            map.remove(&oldest);
        }
    }
    map.insert(key, value);
}

fn option_regressed(previous: Option<View>, current: Option<View>) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => current < previous,
        (Some(_), None) => true,
        (None, _) => false,
    }
}
