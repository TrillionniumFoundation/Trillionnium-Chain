use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};

use trnm_consensus_types::{
    Block, BlockHeader, BlockId, BlockKind, CertificateId, ContextAuthorizedQcV0, Epoch,
    EpochGeometryV0, EquivocationEvidence, GenesisQcV0, Height, QcRef, QcReferenceV0,
    QuorumCertificate, SignatureVerifier, SignedProposalV0, TimeoutCertificateV0, TimeoutVote,
    ValidationError, ValidatorId, ValidatorSet, View, Vote,
};

use crate::{
    block_tree::{Ancestry, BlockTree, PayloadTransition},
    model::{DeferredEffect, PendingPersistence},
    BarrierId, CoreConfig, CoreError, DurablePayloadValidationCompletionV0,
    DurablePayloadValidationObligationV0, DurablePayloadValidationResultV1, Effect, FinalizedTip,
    Input, InvalidPayloadReference, OutboundMessage, PayloadTerminalFact, PayloadTerminalResult,
    PayloadValidationParentV0, PayloadValidationRequest, PayloadValidationResult,
    PayloadValidationRouteV0, PendingStandaloneQcSync, PendingTcHighQcSync, Result, SafetyHalt,
    SafetyState, SignIntent, ValidationId, SAFETY_STATE_SCHEMA_VERSION,
};

type ObservationKey = (Epoch, View, ValidatorId);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedProposal {
    proposal: SignedProposalV0,
    authenticated_parent_timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalFactTransition {
    NotTerminal,
    Repeated,
    Inserted,
    Conflicting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedTcOutcome {
    MissingReferences,
    Complete,
}

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
    pending_validations: BTreeMap<ValidationId, SignedProposalV0>,
    pending_sync_validations: BTreeMap<ValidationId, SignedProposalV0>,
    pending_persistence: Option<PendingPersistence>,
    awaiting_signature: bool,
    // A terminally Valid proposal may complete while an application
    // finalization outbox is active. Retain only that exact, already-
    // authenticated proposal so the finalization acknowledgement can
    // autonomously re-run the ordinary vote checks. This is deliberately
    // volatile: recovery cannot reconstruct the canonical body, authenticated
    // parent context, or frozen runtime inputs from a durable terminal fact.
    finalization_blocked_vote: Option<SignedProposalV0>,
    observed_proposals: BTreeMap<ObservationKey, ObservedProposal>,
    observed_votes: BTreeMap<ObservationKey, Vote>,
    observed_timeouts: BTreeMap<ObservationKey, TimeoutVote>,
    observed_qcs: BTreeMap<View, QuorumCertificate>,
    next_validation_generation: u64,
    replay_required: bool,
}

impl Core {
    /// Starts a core from the exact context-authorized genesis anchor.
    pub fn new<V: SignatureVerifier>(
        config: CoreConfig,
        genesis_qc: GenesisQcV0,
        verifier: &V,
    ) -> Result<Self> {
        config.validate()?;
        if config.validator_set().epoch().get() != 0 {
            return Err(CoreError::InvalidConfig(
                "a new core must start in genesis epoch zero",
            ));
        }
        genesis_qc.matches_trusted_set(config.validator_set())?;
        let safety = SafetyState::from_genesis(
            config.validator_set(),
            genesis_qc,
            config.trusted_genesis_timestamp_ms(),
        )?;
        let value = Self::empty(config, safety, false);
        value.validate_runtime(verifier, true)?;
        Ok(value)
    }

    /// Validates one decoded durable safety state without recovering a live core.
    ///
    /// This authenticates the schema, configured context, cryptographic
    /// witnesses, and every semantic invariant available in the record.
    /// Payload-validation obligations are allowed here as inert persistence
    /// facts; validation neither reissues them nor grants callback authority.
    /// A self-consistent [`SafetyState`] still cannot prove in isolation that
    /// it is the newest durable record.
    pub fn validate_persisted_state_v0<V: SignatureVerifier>(
        config: &CoreConfig,
        state: &SafetyState,
        verifier: &V,
    ) -> Result<()> {
        config.validate()?;
        let replay_required = safety_replay_required(state);
        Self::empty(config.clone(), state.clone(), replay_required).validate_runtime(verifier, true)
    }

    /// Restores the durable safety state after a process restart.
    ///
    /// [`Self::validate_persisted_state_v0`] is the read-only validation
    /// boundary for storage layers that need to authenticate an inert record,
    /// including one that still contains payload-validation obligations. This
    /// recovery boundary deliberately remains stricter: obligations cannot be
    /// reissued until an authenticated replay-ticket protocol exists.
    ///
    /// If `state.pending_sign()` is present, the caller must feed `Resume` and
    /// the core will request precisely that already-persisted signing root.
    /// The volatile block tree is rebuilt by replaying verified proposals and
    /// certificates from the finalized tip through the durable high QC; stale
    /// replay inputs never cause a vote. The storage/signer integration must
    /// reject a snapshot whose revision or signing watermarks precede its
    /// append-only sign journal.
    pub fn recover<V: SignatureVerifier>(
        config: CoreConfig,
        state: SafetyState,
        verifier: &V,
    ) -> Result<Self> {
        Self::validate_persisted_state_v0(&config, &state, verifier)?;
        if !state.payload_validation_obligations().is_empty() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations require an authenticated replay ticket before recovery can reissue them",
            ));
        }
        let replay_required = safety_replay_required(&state);
        Ok(Self::empty(config, state, replay_required))
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

    fn payload_validation_slot_count(&self) -> Result<usize> {
        self.safety
            .payload_validation_obligations()
            .len()
            .checked_add(self.safety.payload_validation_completions().len())
            .ok_or(CoreError::ArithmeticOverflow(
                "payload validation durable slots",
            ))
    }

    /// Freezes the only parent authority which may accompany this exact
    /// payload-validation generation.
    ///
    /// A speculative parent is recovered from the already-authenticated block
    /// tree. A positive-height finalized parent is recovered from the durable
    /// finalization proof rather than from caller input. The synthetic genesis
    /// anchor intentionally carries no invented state root.
    fn payload_validation_parent(
        &self,
        id: ValidationId,
        block: &Block,
    ) -> Result<PayloadValidationParentV0> {
        let header = block.header();
        let block_id = block.id();
        if id.block_id() != block_id {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: block_id,
                received: id.block_id(),
            });
        }
        if id.view() != header.view() {
            return Err(CoreError::WrongView {
                expected: header.view(),
                received: id.view(),
            });
        }

        let finalized = self.safety.finalized();
        let parent = if header.parent_id() == finalized.block_id() {
            if finalized.height().get() == 0 {
                PayloadValidationParentV0::trusted_genesis(finalized)
            } else {
                let durable = self
                    .safety
                    .last_finalization()
                    .ok_or(CoreError::InvalidRecovery(
                        "positive finalized payload parent lacks its durable finalization proof",
                    ))?;
                let exact = durable.proof().finalized_block().header();
                if exact.id() != finalized.block_id()
                    || exact.height() != finalized.height()
                    || exact.view() != finalized.view()
                    || exact.timestamp_ms() != finalized.timestamp_ms()
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable finalization header differs from payload parent tip",
                    ));
                }
                PayloadValidationParentV0::from_exact_header(exact.clone())
            }
        } else {
            let exact = self
                .blocks
                .header(header.parent_id())
                .ok_or(CoreError::MissingBlock(header.parent_id()))?;
            PayloadValidationParentV0::from_exact_header(exact.clone())
        };

        let tip = parent.tip();
        if header.parent_id() != tip.block_id()
            || header.height() != tip.height().checked_next()?
            || header.genesis_hash() != self.config.validator_set().genesis_hash()
            || header.chain_id() != self.config.validator_set().chain_id()
            || header.protocol_version() != self.config.validator_set().protocol_version()
            || header.epoch() != self.config.validator_set().epoch()
            || header.validator_set_id() != self.config.validator_set().id()
            || header.consensus_parameters_hash() != self.config.consensus_parameters().hash()
        {
            return Err(CoreError::UnsafeProposal);
        }
        if let Some(exact) = parent.exact_header() {
            if exact.id() != tip.block_id()
                || exact.height() != tip.height()
                || exact.view() != tip.view()
                || exact.timestamp_ms() != tip.timestamp_ms()
                || !payload_parent_context_matches_target_v0(header, exact)?
            {
                return Err(CoreError::UnsafeProposal);
            }
        }
        Ok(parent)
    }

    fn payload_validation_request_from_obligation(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Result<PayloadValidationRequest> {
        let obligation = self
            .safety
            .payload_validation_obligations()
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .ok()
            .and_then(|index| self.safety.payload_validation_obligations().get(index))
            .filter(|obligation| obligation.route() == route)
            .ok_or(CoreError::InvalidRecovery(
                "deferred payload validation has no exact durable obligation",
            ))?;
        let pending = match route {
            PayloadValidationRouteV0::Proposal => self.pending_validations.get(&id),
            PayloadValidationRouteV0::Synced => self.pending_sync_validations.get(&id),
        }
        .ok_or(CoreError::InvalidRecovery(
            "deferred payload validation has no exact volatile proposal",
        ))?;
        if pending != obligation.proposal() {
            return Err(CoreError::InvalidRecovery(
                "deferred payload validation proposal differs from its durable obligation",
            ));
        }
        Ok(PayloadValidationRequest::new(
            route,
            id,
            obligation.proposal().block().clone(),
            obligation.parent().clone(),
        ))
    }

    /// Applies one deterministic input and returns ordered effects.
    pub fn step<V: SignatureVerifier>(
        &mut self,
        input: Input,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        // Reject busy/stale inputs before cloning bounded protocol state.
        // This is both a DoS boundary and a guarantee that a rejected input
        // cannot perturb volatile observation caches.
        self.reject_while_busy(&input)?;
        // Authenticate peer-supplied consensus messages before cloning the
        // transactional state snapshot. Handlers deliberately repeat these
        // checks after the clone so this admission boundary does not change
        // their validation order or semantics.
        self.preauthenticate_input(&input, verifier)?;
        let previous_safety = self.safety.clone();
        let mut next = self.clone();
        let effects = next.apply(input, verifier)?;
        next.validate_runtime(verifier, false)?;
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
        let next_validation_generation = safety
            .payload_validation_obligations()
            .iter()
            .map(DurablePayloadValidationObligationV0::id)
            .chain(
                safety
                    .payload_validation_completions()
                    .iter()
                    .map(DurablePayloadValidationCompletionV0::id),
            )
            .map(|id| id.generation())
            .fold(safety.revision(), core::cmp::max);
        let mut observed_qcs: BTreeMap<View, QuorumCertificate> = BTreeMap::new();
        for certificate in [safety.locked_qc(), safety.high_qc()]
            .into_iter()
            .filter_map(QcReferenceV0::as_ordinary)
        {
            match observed_qcs.get(&certificate.view()) {
                Some(existing)
                    if existing.block_id() == certificate.block_id()
                        && existing.id() >= certificate.id() => {}
                _ => {
                    observed_qcs.insert(certificate.view(), certificate.clone());
                }
            }
        }
        if let Some(pending) = safety.pending_standalone_qc_sync() {
            for certificate in core::iter::once(pending.active()).chain(pending.backlog()) {
                match observed_qcs.get(&certificate.view()) {
                    Some(existing)
                        if existing.block_id() == certificate.block_id()
                            && existing.id() >= certificate.id() => {}
                    _ => {
                        observed_qcs.insert(certificate.view(), certificate.clone());
                    }
                }
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
            finalization_blocked_vote: None,
            observed_proposals: BTreeMap::new(),
            observed_votes: BTreeMap::new(),
            observed_timeouts: BTreeMap::new(),
            observed_qcs,
            next_validation_generation,
            replay_required,
        }
    }

    fn apply<V: SignatureVerifier>(&mut self, input: Input, verifier: &V) -> Result<Vec<Effect>> {
        match input {
            Input::Resume => self.resume(verifier),
            Input::Proposal(proposal) => self.handle_proposal(*proposal, verifier),
            Input::SyncedProposal(proposal) => self.handle_synced_proposal(*proposal, verifier),
            Input::Vote(vote) => self.handle_vote(vote, verifier),
            Input::TimeoutVote(vote) => self.handle_timeout_vote(vote, verifier),
            Input::QuorumCertificate(certificate) => self.handle_qc(certificate, verifier),
            Input::TimeoutCertificate(certificate) => self.handle_tc(certificate, verifier),
            Input::LocalTimeout { epoch, view } => self.handle_local_timeout(epoch, view),
            Input::PayloadValidated { id, result } => {
                self.handle_payload_validated(id, result, verifier)
            }
            Input::SyncedPayloadValidated { id, result } => {
                self.handle_synced_payload_validated(id, result, verifier)
            }
            Input::CancelSyncedPayloadValidation { id } => {
                self.handle_cancel_synced_payload_validation(id)
            }
            Input::StorageAck { barrier } => self.handle_storage_ack(barrier),
            Input::FinalizationApplied { proof_id } => {
                self.handle_finalization_applied(proof_id, verifier)
            }
            Input::SafetyReplayComplete => self.handle_replay_complete(verifier),
            Input::SignatureReady { id, signature } => {
                self.handle_signature(id, signature, verifier)
            }
        }
    }

    fn preauthenticate_input<V: SignatureVerifier>(
        &self,
        input: &Input,
        verifier: &V,
    ) -> Result<()> {
        match input {
            Input::Proposal(proposal) => self
                .verify_proposal_or_missing_parent(proposal, verifier)
                .map(|_| ()),
            Input::SyncedProposal(proposal) => self.verify_proposal(proposal, verifier).map(|_| ()),
            Input::Vote(vote) => {
                vote.verify(self.config.validator_set(), verifier)?;
                self.require_epoch(vote.epoch())?;
                self.require_pre_checkpoint_height(vote.height())
            }
            Input::TimeoutVote(vote) => {
                vote.verify(self.config.validator_set(), verifier)?;
                self.require_epoch(vote.epoch())?;
                self.require_pre_checkpoint_height(vote.high_qc().height())
            }
            Input::QuorumCertificate(certificate) => self.verify_ordinary_qc(certificate, verifier),
            Input::TimeoutCertificate(certificate) => {
                self.require_epoch(certificate.epoch())?;
                for referenced in certificate.referenced_qcs() {
                    self.reject_epoch_anchor(referenced)?;
                }
                certificate.verify(self.config.validator_set(), None, verifier)?;
                Ok(())
            }
            Input::Resume
            | Input::LocalTimeout { .. }
            | Input::PayloadValidated { .. }
            | Input::SyncedPayloadValidated { .. }
            | Input::CancelSyncedPayloadValidation { .. }
            | Input::StorageAck { .. }
            | Input::FinalizationApplied { .. }
            | Input::SafetyReplayComplete
            | Input::SignatureReady { .. } => Ok(()),
        }
    }

    fn reject_while_busy(&self, input: &Input) -> Result<()> {
        if let Input::CancelSyncedPayloadValidation { id } = input {
            if !self.pending_sync_validations.contains_key(id) {
                return Err(CoreError::UnknownValidation(id.block_id()));
            }
        }
        // A host callback can be safety-critical even while another durable
        // outbox is active. Widen the busy gate only for the exact, still-
        // registered generation; arbitrary callback IDs remain unable to
        // interrupt signing, finalization, or TC sync.
        let registered_validation = match input {
            Input::PayloadValidated { id, .. } => {
                self.pending_validations.contains_key(id)
                    || self
                        .payload_validation_completion(PayloadValidationRouteV0::Proposal, *id)
                        .is_some()
            }
            Input::SyncedPayloadValidated { id, .. } => {
                self.pending_sync_validations.contains_key(id)
                    || self
                        .payload_validation_completion(PayloadValidationRouteV0::Synced, *id)
                        .is_some()
            }
            Input::CancelSyncedPayloadValidation { id } => {
                self.pending_sync_validations.contains_key(id)
            }
            _ => false,
        };
        // This is only an admission probe over not-yet-authenticated bytes. It
        // can widen the busy gate, never authorize a transition: `step` still
        // performs full preauthentication before the transactional clone.
        let durable_conflict_probe = match input {
            Input::QuorumCertificate(certificate) => {
                self.payload_is_deterministically_invalid(certificate.block_id())
                    || self.durable_qcs().into_iter().any(|durable| {
                        durable.view() == certificate.view()
                            && durable.block_id() != certificate.block_id()
                    })
            }
            Input::TimeoutCertificate(certificate) => {
                let durable_qcs = self.durable_qcs();
                certificate
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| {
                        self.payload_is_deterministically_invalid(referenced.block_id())
                            || durable_qcs.iter().any(|durable| {
                                durable.view() == referenced.view()
                                    && durable.block_id() != referenced.block_id()
                            })
                    })
            }
            Input::Proposal(proposal) | Input::SyncedProposal(proposal) => {
                let durable_qcs = self.durable_qcs();
                proposal_referenced_qcs(proposal)
                    .into_iter()
                    .any(|referenced| {
                        self.payload_is_deterministically_invalid(referenced.block_id())
                            || durable_qcs.iter().any(|durable| {
                                durable.view() == referenced.view()
                                    && durable.block_id() != referenced.block_id()
                            })
                    })
            }
            _ => false,
        };
        if self.pending_persistence.is_some() && !matches!(input, Input::StorageAck { .. }) {
            return Err(CoreError::Busy(
                "waiting for durable safety-state acknowledgement",
            ));
        }
        if self.safety.safety_halt().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::StorageAck { .. }
                    | Input::CancelSyncedPayloadValidation { .. }
            )
        {
            return Err(CoreError::Busy(
                "consensus is safety-halted pending operator recovery",
            ));
        }
        if self.awaiting_signature
            && !matches!(
                input,
                Input::SignatureReady { .. } | Input::StorageAck { .. } | Input::Resume
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy("waiting for the requested signature"));
        }
        if self.safety.pending_sign().is_some()
            && !self.awaiting_signature
            && self.pending_persistence.is_none()
            && !matches!(input, Input::Resume)
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy("persisted signing intent must be resumed"));
        }
        if self.safety.pending_finalize().is_some()
            && !matches!(
                input,
                Input::Resume | Input::StorageAck { .. } | Input::FinalizationApplied { .. }
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "waiting for application finalization acknowledgement",
            ));
        }
        if self.safety.pending_tc_high_qc_sync().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::Proposal(_)
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::FinalizationApplied { .. }
                    | Input::SafetyReplayComplete
                    | Input::QuorumCertificate(_)
                    | Input::TimeoutCertificate(_)
                    | Input::LocalTimeout { .. }
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "only the durable TC high-QC sync target may progress",
            ));
        }
        if self.safety.pending_standalone_qc_sync().is_some()
            && !matches!(
                input,
                Input::Resume
                    | Input::Proposal(_)
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::FinalizationApplied { .. }
                    | Input::SafetyReplayComplete
                    | Input::QuorumCertificate(_)
                    | Input::TimeoutCertificate(_)
                    | Input::LocalTimeout { .. }
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
            && !durable_conflict_probe
        {
            return Err(CoreError::Busy(
                "only durable certified-block sync obligations may progress",
            ));
        }
        if self.replay_required
            && !durable_conflict_probe
            && !matches!(
                input,
                Input::Resume
                    | Input::SyncedProposal(_)
                    | Input::StorageAck { .. }
                    | Input::FinalizationApplied { .. }
                    | Input::SafetyReplayComplete
                    | Input::SignatureReady { .. }
            )
            && !registered_validation
        {
            return Err(CoreError::Busy(
                "only safety replay and durable outbox recovery are allowed until every persisted anchor is verified",
            ));
        }
        Ok(())
    }

    fn resume<V: SignatureVerifier>(&mut self, verifier: &V) -> Result<Vec<Effect>> {
        if let Some(halt) = self.safety.safety_halt().cloned() {
            return Ok(vec![Effect::SafetyHalted(Box::new(halt))]);
        }
        if let Some(intent) = self.safety.pending_sign().cloned() {
            self.awaiting_signature = true;
            return Ok(vec![self.signature_effect(&intent)?]);
        }
        if let Some(proof_id) = self.safety.pending_finalize() {
            return Ok(vec![self.finalize_effect(proof_id)?]);
        }
        if self.replay_required {
            return Ok(vec![Effect::RequestSafetyReplay {
                finalized: self.safety.finalized(),
                high_qc: self.safety.high_qc().qc_ref(),
                locked_qc: self.safety.locked_qc().qc_ref(),
            }]);
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            let mut effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            if matches!(effects.as_slice(), [Effect::RequestTcHighQcSync { .. }]) {
                effects.insert(
                    0,
                    Effect::ArmViewTimer {
                        epoch: self.safety.epoch(),
                        view: self.safety.current_view(),
                    },
                );
            }
            return Ok(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            let mut effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            if matches!(effects.as_slice(), [Effect::RequestStandaloneQcSync { .. }]) {
                effects.insert(
                    0,
                    Effect::ArmViewTimer {
                        epoch: self.safety.epoch(),
                        view: self.safety.current_view(),
                    },
                );
            }
            return Ok(effects);
        }
        Ok(vec![Effect::ArmViewTimer {
            epoch: self.safety.epoch(),
            view: self.safety.current_view(),
        }])
    }

    fn handle_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let parent_timestamp_ms = self.verify_proposal_or_missing_parent(&proposal, verifier)?;
        let mut side_effects = Vec::new();
        if let Some(parent_timestamp_ms) = parent_timestamp_ms {
            if let Some(evidence) = self.observe_proposal(&proposal, parent_timestamp_ms)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }
        for referenced_qc in proposal_referenced_qcs(&proposal) {
            for vote in referenced_qc.votes() {
                if let Some(evidence) = self.observe_vote(vote)? {
                    side_effects.push(Effect::Evidence(evidence));
                }
            }
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                let mut effects = self.persist_safety_halt(halt)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            side_effects.extend(
                self.observe_timeout_certificate(certificate)?
                    .into_iter()
                    .map(Effect::Evidence),
            );
        }
        if let Some(certificate) = proposal_referenced_qcs(&proposal)
            .into_iter()
            .find(|certificate| self.payload_is_deterministically_invalid(certificate.block_id()))
        {
            let mut effects =
                self.persist_proposal_invalid_payload(&proposal, certificate.clone())?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        let before = self.safety.clone();
        if let Some(certificate) = proposal.witness().timeout_certificate().cloned() {
            let had_pending_tc = self.safety.pending_tc_high_qc_sync().is_some();
            match self.apply_authenticated_tc(&certificate, verifier)? {
                AuthenticatedTcOutcome::MissingReferences => {
                    if self.safety == before {
                        side_effects.push(self.tc_high_qc_sync_effect()?);
                        return Ok(side_effects);
                    }
                    let mut deferred = Vec::new();
                    if self.safety.current_view() > before.current_view() {
                        deferred.push(DeferredEffect::ArmViewTimer);
                    }
                    deferred.push(DeferredEffect::RequestTcHighQcSync);
                    let mut effects = self.persist(deferred)?;
                    effects.extend(side_effects);
                    return Ok(effects);
                }
                AuthenticatedTcOutcome::Complete
                    if had_pending_tc || self.safety.pending_standalone_qc_sync().is_some() =>
                {
                    // A previously durable TC or older standalone obligation
                    // completes/rotates before the dependent child is admitted.
                    return self.persist_carried_qc_transition(&before, side_effects);
                }
                AuthenticatedTcOutcome::Complete => {}
            }
        } else if let Some(certificate) = proposal.witness().justify_qc().as_ordinary().cloned() {
            let ready = self.qc_is_ready_for_adoption(&certificate)?;
            if self.safety.pending_tc_high_qc_sync().is_some()
                || self.safety.pending_standalone_qc_sync().is_some()
                || !ready
            {
                // A proposal independently authenticates its exact justify QC.
                // If that QC cannot complete §6 locally, give it precisely the
                // direct-QC durable active/backlog treatment and stop before
                // inserting or voting for the dependent child.
                return self.handle_authenticated_qc(certificate, verifier, side_effects);
            }
            self.process_verified_ready_qc(&certificate, verifier)?;
        } else if self.safety.pending_tc_high_qc_sync().is_some() {
            side_effects.push(self.tc_high_qc_sync_effect()?);
            return Ok(side_effects);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            side_effects.push(self.standalone_qc_sync_effect()?);
            return Ok(side_effects);
        }

        if let Some(certificate) = proposal.witness().justify_qc().as_ordinary() {
            let durably_subsumed = self.qc_is_durably_subsumed(certificate)?;
            if durably_subsumed && certificate.block_id() != self.safety.finalized().block_id() {
                // A locally-known stale competing prefix is operationally the
                // same as a pruned one.  The authenticated carrier may have
                // advanced view through its TC, but it must never extend that
                // prefix merely because its header/body remain cached.
                return self.persist_carried_qc_transition(&before, side_effects);
            }
        }

        if parent_timestamp_ms.is_none() {
            // The only missing-parent QC that reaches this point was already
            // classified as durably subsumed at or below finality. Learning it
            // is an idempotent observation; the stale carrier itself needs no
            // body, timestamp, or child admission and must not create a sync
            // loop.
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        let header = proposal.block().header();
        if header.view() < self.safety.current_view()
            || header.height() <= self.safety.finalized().height()
        {
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        match self.blocks.validate_proposal_parent(
            header,
            proposal.witness().justify_qc().qc_ref(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            // An ordinary justify which reached this point was already proved
            // ready against the same tree and finalized tip. Synthetic anchors
            // are exact trusted context, so Unknown is always fail-closed.
            Ancestry::Unknown => return Err(CoreError::MissingBlock(header.parent_id())),
            Ancestry::Conflicts => return Err(CoreError::UnsafeProposal),
        }
        if self
            .blocks
            .has_different_fixed_witness(header, proposal.witness())?
        {
            return self.persist_carried_qc_transition(&before, side_effects);
        }
        let protected = self.protected_blocks();
        self.blocks.insert_verified_proposal(
            proposal.block().header().clone(),
            proposal.witness().clone(),
            &protected,
        )?;
        self.restore_durable_payload_fact(proposal.block().id())?;

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
            if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
                deferred.push(DeferredEffect::Finalize);
            }
            if let Some((id, true)) = validation {
                deferred.push(DeferredEffect::ValidatePayload(id));
            }
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if validation.is_none() && self.blocks.payload_is_valid(proposal.block().id()) {
            if let Some(mut effects) =
                self.persist_observed_qc_for_validated_block(proposal.block().id(), verifier)?
            {
                effects.extend(side_effects);
                return Ok(effects);
            }
            let mut effects = self.try_vote_validated_proposal(&proposal)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        Ok(side_effects)
    }

    fn persist_carried_qc_transition(
        &mut self,
        before: &SafetyState,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if &self.safety == before {
            return Ok(side_effects);
        }
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        let mut effects = self.persist(deferred)?;
        effects.append(&mut side_effects);
        Ok(effects)
    }

    /// Installs verified replay ancestry and schedules execution validation.
    /// This path deliberately never learns a QC, changes view, or votes.
    fn handle_synced_proposal<V: SignatureVerifier>(
        &mut self,
        proposal: SignedProposalV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let parent_timestamp_ms = self.verify_proposal(&proposal, verifier)?;
        let mut side_effects = Vec::new();
        if let Some(evidence) = self.observe_proposal(&proposal, parent_timestamp_ms)? {
            side_effects.push(Effect::Evidence(evidence));
        }
        for referenced_qc in proposal_referenced_qcs(&proposal) {
            for vote in referenced_qc.votes() {
                if let Some(evidence) = self.observe_vote(vote)? {
                    side_effects.push(Effect::Evidence(evidence));
                }
            }
            if let Some(halt) = self.observe_qc(referenced_qc)? {
                let mut effects = self.persist_safety_halt(halt)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            side_effects.extend(
                self.observe_timeout_certificate(certificate)?
                    .into_iter()
                    .map(Effect::Evidence),
            );
        }
        if let Some(certificate) = proposal_referenced_qcs(&proposal)
            .into_iter()
            .find(|certificate| self.payload_is_deterministically_invalid(certificate.block_id()))
        {
            let mut effects =
                self.persist_proposal_invalid_payload(&proposal, certificate.clone())?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        let header = proposal.block().header();
        if header.height() <= self.safety.finalized().height() {
            return Ok(side_effects);
        }
        if self.replay_required {
            if header.height().get() > self.replay_max_height() {
                return Err(CoreError::StaleInput);
            }
        } else if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            if header.height().get() > pending_tc_sync_max_height(pending) {
                return Err(CoreError::StaleInput);
            }
        } else if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            if header.height().get() > pending_standalone_sync_max_height(pending) {
                return Err(CoreError::StaleInput);
            }
        }
        match self.blocks.validate_proposal_parent(
            header,
            proposal.witness().justify_qc().qc_ref(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            Ancestry::Unknown => return Err(CoreError::MissingBlock(header.parent_id())),
            Ancestry::Conflicts => return Err(CoreError::UnsafeProposal),
        }
        if self
            .blocks
            .has_different_fixed_witness(header, proposal.witness())?
        {
            return Ok(side_effects);
        }
        let protected = self.protected_blocks();
        self.blocks.insert_verified_proposal(
            header.clone(),
            proposal.witness().clone(),
            &protected,
        )?;
        self.restore_durable_payload_fact(proposal.block().id())?;
        if self.blocks.payload_is_known(proposal.block().id()) {
            let mut effects = if self.blocks.payload_is_valid(proposal.block().id()) {
                if self.replay_required {
                    Vec::new()
                } else if self.safety.pending_tc_high_qc_sync().is_some() {
                    self.try_complete_pending_tc_high_qc_sync(verifier)?
                } else if self.safety.pending_standalone_qc_sync().is_some() {
                    self.try_complete_pending_standalone_qc_sync(verifier)?
                } else {
                    self.persist_observed_qc_for_validated_block(proposal.block().id(), verifier)?
                        .unwrap_or_default()
                }
            } else {
                Vec::new()
            };
            effects.extend(side_effects);
            return Ok(effects);
        }
        let (id, is_new) = self.register_sync_validation(&proposal)?;
        if !is_new {
            return Ok(side_effects);
        }
        let mut effects = self.persist(vec![DeferredEffect::ValidateSyncedPayload(id)])?;
        effects.extend(side_effects);
        Ok(effects)
    }

    fn ensure_payload_validation_proposal_resource_bound(
        &self,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let actual = proposal.durable_validation_resource_size_v0()?;
        let maximum = self
            .config
            .consensus_parameters()
            .max_consensus_message_bytes() as usize;
        if actual > maximum {
            return Err(CoreError::PayloadValidationResourceTooLarge { actual, maximum });
        }
        Ok(())
    }

    fn verify_proposal<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<u64> {
        if proposal.block().logical_block_size() > self.config.max_block_bytes() {
            return Err(CoreError::BlockTooLarge {
                actual: proposal.block().logical_block_size(),
                maximum: self.config.max_block_bytes(),
            });
        }
        self.ensure_payload_validation_proposal_resource_bound(proposal)?;
        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
        self.reject_epoch_anchor(proposal.witness().justify_qc())?;
        if proposal.witness().epoch_anchor_authorization().is_some() {
            return Err(CoreError::UnsupportedEpochAnchor);
        }
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            for referenced in certificate.referenced_qcs() {
                self.reject_epoch_anchor(referenced)?;
            }
        }
        let parent_timestamp_ms = match proposal.witness().justify_qc().as_synthetic() {
            Some(ContextAuthorizedQcV0::Genesis(_)) => self.config.trusted_genesis_timestamp_ms(),
            Some(ContextAuthorizedQcV0::Epoch(_)) => return Err(CoreError::UnsupportedEpochAnchor),
            None if header.parent_id() == self.safety.finalized().block_id() => {
                self.safety.finalized().timestamp_ms()
            }
            None => self
                .blocks
                .header(header.parent_id())
                .map(BlockHeader::timestamp_ms)
                .ok_or(CoreError::MissingBlock(header.parent_id()))?,
        };
        proposal.verify(
            self.config.validator_set(),
            None,
            self.config.consensus_parameters(),
            parent_timestamp_ms,
            verifier,
        )?;
        Ok(parent_timestamp_ms)
    }

    /// Authenticates a network proposal even when its certified parent header
    /// is not local yet. Only the parent-relative timestamp check is deferred;
    /// the complete envelope shape, exact parent-QC relation, leader, ordinary
    /// certificates, optional TC, and proposer signature are verified first.
    fn verify_proposal_or_missing_parent<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<Option<u64>> {
        match self.verify_proposal(proposal, verifier) {
            Ok(parent_timestamp_ms) => Ok(Some(parent_timestamp_ms)),
            Err(CoreError::MissingBlock(block_id))
                if proposal
                    .witness()
                    .justify_qc()
                    .as_ordinary()
                    .is_some_and(|certificate| {
                        certificate.block_id() == block_id
                            && proposal.block().header().parent_id() == block_id
                    }) =>
            {
                self.verify_proposal_without_parent_context(proposal, verifier)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn verify_proposal_without_parent_context<V: SignatureVerifier>(
        &self,
        proposal: &SignedProposalV0,
        verifier: &V,
    ) -> Result<()> {
        if proposal.block().logical_block_size() > self.config.max_block_bytes() {
            return Err(CoreError::BlockTooLarge {
                actual: proposal.block().logical_block_size(),
                maximum: self.config.max_block_bytes(),
            });
        }
        self.ensure_payload_validation_proposal_resource_bound(proposal)?;
        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
        if proposal.witness().epoch_anchor_authorization().is_some() {
            return Err(CoreError::UnsupportedEpochAnchor);
        }
        proposal.validate_shape(self.config.validator_set(), None)?;
        if leader_for(self.config.validator_set(), header.view()) != header.proposer_id() {
            return Err(CoreError::Protocol(ValidationError::InvalidProposal(
                "proposer is not the scheduled leader",
            )));
        }

        self.verify_qc_reference(proposal.witness().justify_qc(), verifier)?;
        if let Some(certificate) = proposal.witness().timeout_certificate() {
            self.require_epoch(certificate.epoch())?;
            for referenced in certificate.referenced_qcs() {
                self.reject_epoch_anchor(referenced)?;
            }
            certificate.verify(self.config.validator_set(), None, verifier)?;
        }

        let proposer = self
            .config
            .validator_set()
            .validator(header.proposer_id())
            .ok_or_else(|| {
                CoreError::Protocol(ValidationError::UnknownValidator(Box::new(
                    header.proposer_id(),
                )))
            })?;
        if !verifier.verify(
            proposer,
            &proposal.proposal_signing_root(),
            proposal.witness().proposer_signature(),
        ) {
            return Err(CoreError::Protocol(ValidationError::InvalidSignature(
                Box::new(header.proposer_id()),
            )));
        }
        Ok(())
    }

    fn reject_epoch_anchor(&self, reference: &QcReferenceV0) -> Result<()> {
        if let Some(certificate) = reference.as_ordinary() {
            if certificate.view().get() == 0 || certificate.height().get() == 0 {
                return Err(CoreError::InvalidOrdinaryCertificate);
            }
            self.require_pre_checkpoint_height(certificate.height())?;
            return Ok(());
        }
        match reference.as_synthetic() {
            Some(ContextAuthorizedQcV0::Epoch(_)) => Err(CoreError::UnsupportedEpochAnchor),
            Some(ContextAuthorizedQcV0::Genesis(anchor)) => {
                anchor.matches_trusted_set(self.config.validator_set())?;
                Ok(())
            }
            None => Err(CoreError::InvalidOrdinaryCertificate),
        }
    }

    fn handle_payload_validated<V: SignatureVerifier>(
        &mut self,
        id: ValidationId,
        result: PayloadValidationResult,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        Self::validate_payload_capability(id, result)?;
        let route = PayloadValidationRouteV0::Proposal;
        if let Some(effects) = self.handle_resolved_validation(route, id, result)? {
            return Ok(effects);
        }
        let proposal = self
            .pending_validations
            .get(&id)
            .cloned()
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        let pending_block_id = proposal.block().id();
        if pending_block_id != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: pending_block_id,
                received: id.block_id(),
            });
        }
        self.require_payload_validation_obligation(route, id, &proposal)?;
        self.pending_validations.remove(&id);
        self.remove_payload_validation_obligation(route, id)?;
        self.record_payload_validation_completion(route, id, result)?;
        let block_id = proposal.block().id();
        let transition = self.blocks.record_payload_validation(block_id, result)?;
        let fact_transition = self.record_payload_terminal_fact(block_id, result)?;
        if transition == PayloadTransition::ConflictingTerminalResult
            || fact_transition == TerminalFactTransition::Conflicting
        {
            return self
                .persist_payload_safety_halt(SafetyHalt::conflicting_payload_validation(block_id));
        }
        if result.is_deterministically_invalid() {
            if let Some(reference) = self.invalid_payload_reference(block_id) {
                let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)?;
                return self.persist_payload_safety_halt(halt);
            }
            // A terminally invalid ordinary proposal which is not certified or
            // named by durable safety state remains only a bounded negative
            // cache entry. Persist it before accepting more consensus input so
            // crash or block-tree eviction cannot make it validation-unknown.
            return self.persist(Vec::new());
        }
        if result.is_unavailable() {
            // Consume this source-scoped generation, but preserve the header.
            // A TC target must remain durable and be requested again exactly.
            if self.safety.pending_tc_high_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestTcHighQcSync]);
            }
            if self.safety.pending_standalone_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestStandaloneQcSync]);
            }
            return self.persist(Vec::new());
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            // A Valid result may satisfy one of the pending TC's references,
            // but may not create a concurrent safety transition while another
            // durable outbox is active.
            if self.safety.pending_sign().is_some()
                || self.safety.pending_finalize().is_some()
                || self.awaiting_signature
            {
                return self.persist(Vec::new());
            }
            let effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            return self.ensure_payload_validation_cleanup_barrier(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            if self.safety.pending_sign().is_some()
                || self.safety.pending_finalize().is_some()
                || self.awaiting_signature
            {
                return self.persist(Vec::new());
            }
            let effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            return self.ensure_payload_validation_cleanup_barrier(effects);
        }
        if self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.awaiting_signature
        {
            if self.safety.pending_finalize().is_some()
                && self.safety.pending_sign().is_none()
                && !self.awaiting_signature
            {
                self.remember_finalization_blocked_vote(&proposal);
            }
            return self.persist(Vec::new());
        }
        if let Some(effects) = self.persist_observed_qc_for_validated_block(block_id, verifier)? {
            return Ok(effects);
        }
        let effects = self.try_vote_validated_proposal(&proposal)?;
        self.ensure_payload_validation_cleanup_barrier(effects)
    }

    fn remember_finalization_blocked_vote(&mut self, proposal: &SignedProposalV0) {
        let header = proposal.block().header();
        if header.view() != self.safety.current_view()
            || self.safety.payload_terminal_result(proposal.block().id())
                != Some(PayloadTerminalResult::Valid)
            || !self.blocks.payload_is_valid(proposal.block().id())
            || !self.is_exact_observed_proposal(proposal)
        {
            return;
        }

        // A validator set has one scheduled leader per view and the
        // observation cache retains that leader's first authenticated
        // proposal. Consequently this option is a complete, deterministic
        // bound rather than a lossy queue.
        self.finalization_blocked_vote = Some(proposal.clone());
    }

    fn is_exact_observed_proposal(&self, proposal: &SignedProposalV0) -> bool {
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        self.observed_proposals
            .get(&key)
            .is_some_and(|observed| observed.proposal == *proposal)
    }

    fn try_vote_validated_proposal(&mut self, proposal: &SignedProposalV0) -> Result<Vec<Effect>> {
        if !self.stage_vote_validated_proposal(proposal)? {
            return Ok(Vec::new());
        }
        self.persist(vec![DeferredEffect::RequestSignature])
    }

    fn stage_vote_validated_proposal(&mut self, proposal: &SignedProposalV0) -> Result<bool> {
        if self.safety.pending_standalone_qc_sync().is_some() {
            return Ok(false);
        }
        if proposal.block().header().view() != self.safety.current_view() {
            return Ok(false);
        }
        if self.replay_required {
            return Err(CoreError::Busy(
                "safety ancestry replay must complete before a new signing intent",
            ));
        }
        if self
            .safety
            .last_voted_view()
            .is_some_and(|view| view >= proposal.block().header().view())
        {
            return Ok(false);
        }
        if self.safety.pending_sign().is_some() {
            return Err(CoreError::ConcurrentSignIntent);
        }

        let justify = proposal.witness().justify_qc().qc_ref();
        if justify.block_id() != self.safety.finalized().block_id()
            && !self.blocks.contains_header(justify.block_id())
        {
            // A QC proves votes for an identifier, not availability or the
            // certified parent's header. Never unlock/vote across that gap.
            return Ok(false);
        }
        match self.blocks.validated_ancestry(
            proposal.block().id(),
            self.safety.finalized(),
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => {}
            Ancestry::Unknown | Ancestry::Conflicts => return Ok(false),
        }
        let extends_lock = self.blocks.extends(
            proposal.block().id(),
            self.safety.locked_qc().qc_ref().block_id(),
        );
        let unlocks = justify.view() > self.safety.locked_qc().qc_ref().view();
        if !extends_lock && !unlocks {
            return Ok(false);
        }

        let header = proposal.block().header();
        self.require_supported_proposal_header(header)?;
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
        Ok(true)
    }

    fn try_stage_finalization_blocked_vote<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<bool> {
        let Some(proposal) = self.finalization_blocked_vote.take() else {
            return Ok(false);
        };
        if self.replay_required
            || self.awaiting_signature
            || self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.safety.pending_tc_high_qc_sync().is_some()
            || self.safety.pending_standalone_qc_sync().is_some()
            || proposal.block().header().view() != self.safety.current_view()
            || self.safety.payload_terminal_result(proposal.block().id())
                != Some(PayloadTerminalResult::Valid)
            || !self.blocks.payload_is_valid(proposal.block().id())
            || !self.is_exact_observed_proposal(&proposal)
        {
            return Ok(false);
        }

        // Finality may have advanced the authenticated parent context or made
        // the proposal stale. Re-run the complete envelope/leader/signature
        // verification, then the ordinary ancestry, lock, and watermark rules.
        // A failed re-check only drops this volatile liveness hint; it must not
        // roll back an already-applied application finalization.
        let Ok(parent_timestamp_ms) = self.verify_proposal(&proposal, verifier) else {
            return Ok(false);
        };
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        if self.observed_proposals.get(&key).is_none_or(|observed| {
            observed.proposal != proposal
                || observed.authenticated_parent_timestamp_ms != parent_timestamp_ms
        }) {
            return Ok(false);
        }
        self.stage_vote_validated_proposal(&proposal)
    }

    fn persist_observed_qc_for_validated_block<V: SignatureVerifier>(
        &mut self,
        block_id: BlockId,
        verifier: &V,
    ) -> Result<Option<Vec<Effect>>> {
        let Some(certificate) = self
            .observed_qcs
            .values()
            .filter(|certificate| certificate.block_id() == block_id)
            .max_by_key(|certificate| qc_order_key(certificate))
            .cloned()
        else {
            return Ok(None);
        };
        let before = self.safety.clone();
        self.process_verified_ready_qc(&certificate, verifier)?;
        if self.safety == before {
            return Ok(None);
        }
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        }
        self.persist(deferred).map(Some)
    }

    fn handle_synced_payload_validated<V: SignatureVerifier>(
        &mut self,
        id: ValidationId,
        result: PayloadValidationResult,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        Self::validate_payload_capability(id, result)?;
        let route = PayloadValidationRouteV0::Synced;
        if let Some(effects) = self.handle_resolved_validation(route, id, result)? {
            return Ok(effects);
        }
        let proposal = self
            .pending_sync_validations
            .get(&id)
            .cloned()
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        let pending_block_id = proposal.block().id();
        if pending_block_id != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: pending_block_id,
                received: id.block_id(),
            });
        }
        self.require_payload_validation_obligation(route, id, &proposal)?;
        self.pending_sync_validations.remove(&id);
        self.remove_payload_validation_obligation(route, id)?;
        self.record_payload_validation_completion(route, id, result)?;
        let block_id = proposal.block().id();
        let transition = self.blocks.record_payload_validation(block_id, result)?;
        let fact_transition = self.record_payload_terminal_fact(block_id, result)?;
        if transition == PayloadTransition::ConflictingTerminalResult
            || fact_transition == TerminalFactTransition::Conflicting
        {
            return self
                .persist_payload_safety_halt(SafetyHalt::conflicting_payload_validation(block_id));
        }
        if result.is_deterministically_invalid() {
            if let Some(reference) = self.invalid_payload_reference(block_id) {
                let halt = SafetyHalt::deterministically_invalid_payload(block_id, reference)?;
                return self.persist_payload_safety_halt(halt);
            }
            return self.persist(Vec::new());
        }
        if result.is_unavailable() {
            if self.replay_required {
                return self.persist(Vec::new());
            }
            if self.safety.pending_tc_high_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestTcHighQcSync]);
            }
            if self.safety.pending_standalone_qc_sync().is_some() {
                return self.persist(vec![DeferredEffect::RequestStandaloneQcSync]);
            }
            return self.persist(Vec::new());
        }
        if self.safety.pending_sign().is_some()
            || self.safety.pending_finalize().is_some()
            || self.awaiting_signature
        {
            return self.persist(Vec::new());
        }
        if self.replay_required {
            return self.persist(Vec::new());
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            let effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            return self.ensure_payload_validation_cleanup_barrier(effects);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            let effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
            return self.ensure_payload_validation_cleanup_barrier(effects);
        }
        if let Some(effects) = self.persist_observed_qc_for_validated_block(block_id, verifier)? {
            return Ok(effects);
        }
        self.persist(Vec::new())
    }

    fn handle_cancel_synced_payload_validation(&mut self, id: ValidationId) -> Result<Vec<Effect>> {
        let proposal = self
            .pending_sync_validations
            .get(&id)
            .cloned()
            .ok_or(CoreError::UnknownValidation(id.block_id()))?;
        self.require_payload_validation_obligation(
            PayloadValidationRouteV0::Synced,
            id,
            &proposal,
        )?;
        self.pending_sync_validations.remove(&id);
        self.remove_payload_validation_obligation(PayloadValidationRouteV0::Synced, id)?;
        self.persist(Vec::new())
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
        let high_qc = self.safety.high_qc().qc_ref();
        self.require_pre_checkpoint_height(high_qc.height())?;
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
                    effects.push(self.signature_effect(&intent)?);
                }
                DeferredEffect::ArmViewTimer => effects.push(Effect::ArmViewTimer {
                    epoch: self.safety.epoch(),
                    view: self.safety.current_view(),
                }),
                DeferredEffect::ValidatePayload(id) => {
                    effects.push(Effect::ValidatePayload(
                        self.payload_validation_request_from_obligation(
                            PayloadValidationRouteV0::Proposal,
                            id,
                        )?,
                    ));
                }
                DeferredEffect::ValidateSyncedPayload(id) => {
                    effects.push(Effect::ValidateSyncedPayload(
                        self.payload_validation_request_from_obligation(
                            PayloadValidationRouteV0::Synced,
                            id,
                        )?,
                    ));
                }
                DeferredEffect::RequestTcHighQcSync => {
                    effects.push(self.tc_high_qc_sync_effect()?);
                }
                DeferredEffect::RequestStandaloneQcSync => {
                    effects.push(self.standalone_qc_sync_effect()?);
                }
                DeferredEffect::SafetyHalted => {
                    let halt = self
                        .safety
                        .safety_halt()
                        .cloned()
                        .ok_or(CoreError::ConflictingCertificate)?;
                    effects.push(Effect::SafetyHalted(Box::new(halt)));
                }
                DeferredEffect::Finalize => {
                    let proof_id = self
                        .safety
                        .pending_finalize()
                        .ok_or(CoreError::UnexpectedFinalizationAck)?;
                    effects.push(self.finalize_effect(proof_id)?);
                }
            }
        }
        Ok(effects)
    }

    fn handle_finalization_applied<V: SignatureVerifier>(
        &mut self,
        proof_id: trnm_consensus_types::CertificateId,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let pending_id = self
            .safety
            .pending_finalize()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if pending_id != proof_id {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        let durable = self
            .safety
            .last_finalization()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if durable.proof_id() != proof_id {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        self.safety.set_pending_finalize(None);
        let drained_standalone = if self.safety.pending_tc_high_qc_sync().is_none() {
            self.drain_ready_pending_standalone_qcs(verifier)?
        } else {
            false
        };
        let mut deferred = Vec::new();
        if drained_standalone {
            deferred.push(DeferredEffect::ArmViewTimer);
        }
        if self.safety.pending_tc_high_qc_sync().is_some() {
            self.finalization_blocked_vote = None;
            deferred.push(DeferredEffect::RequestTcHighQcSync);
        } else if self.safety.pending_finalize().is_some() {
            // A coalesced finalization remains the sole blocker. Keep the
            // volatile candidate for that exact acknowledgement.
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            self.finalization_blocked_vote = None;
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        } else if self.try_stage_finalization_blocked_vote(verifier)? {
            // Clearing the finalization outbox and creating the vote intent
            // share one safety-state write. The signer is requested only by
            // the resulting StorageAck.
            deferred.push(DeferredEffect::RequestSignature);
        }
        self.persist(deferred)
    }

    fn handle_replay_complete<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if self.replay_required {
            let high_ref = self.safety.high_qc().qc_ref();
            let locked_ref = self.safety.locked_qc().qc_ref();
            let mut anchors = vec![high_ref.block_id()];
            if locked_ref.block_id() != self.safety.finalized().block_id() {
                anchors.push(locked_ref.block_id());
            }
            for reference in [self.safety.high_qc(), self.safety.locked_qc()] {
                if let Some(certificate) = reference.as_ordinary() {
                    if certificate.block_id() != self.safety.finalized().block_id() {
                        self.blocks
                            .validate_certificate_binding(certificate)
                            .map_err(|_| {
                                CoreError::InvalidRecovery(
                                    "replayed safety anchor does not match its durable certificate",
                                )
                            })?;
                    }
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
        if self.safety.pending_tc_high_qc_sync().is_some() {
            return self.try_complete_pending_tc_high_qc_sync(verifier);
        }
        if self.safety.pending_standalone_qc_sync().is_some() {
            return self.try_complete_pending_standalone_qc_sync(verifier);
        }
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
        self.require_supported_sign_intent(&intent)?;
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
        let mut effects = vec![Effect::Broadcast(outbound)];
        if self.safety.pending_tc_high_qc_sync().is_some() {
            effects.extend(self.try_complete_pending_tc_high_qc_sync(verifier)?);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            effects.extend(self.try_complete_pending_standalone_qc_sync(verifier)?);
        }
        Ok(effects)
    }

    fn handle_vote<V: SignatureVerifier>(
        &mut self,
        vote: Vote,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        vote.verify(self.config.validator_set(), verifier)?;
        self.require_epoch(vote.epoch())?;
        self.require_pre_checkpoint_height(vote.height())?;
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
        self.require_pre_checkpoint_height(vote.high_qc().height())?;
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
        self.verify_ordinary_qc(&certificate, verifier)?;
        let mut side_effects = Vec::new();
        for vote in certificate.votes() {
            if let Some(evidence) = self.observe_vote(vote)? {
                side_effects.push(Effect::Evidence(evidence));
            }
        }
        if let Some(halt) = self.observe_qc(&certificate)? {
            let mut effects = self.persist_safety_halt(halt)?;
            effects.extend(side_effects);
            return Ok(effects);
        }
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            let mut effects = self.persist_certified_invalid_payload(certificate)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        self.handle_authenticated_qc(certificate, verifier, side_effects)
    }

    /// Applies an already-authenticated and already-observed ordinary QC.
    ///
    /// Proposal carriers use this after observing every certificate in their
    /// signed witness, so the exact justify QC shares the direct-QC durable
    /// catch-up path without double-counting votes or equivocation evidence.
    fn handle_authenticated_qc<V: SignatureVerifier>(
        &mut self,
        certificate: QuorumCertificate,
        verifier: &V,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if self
            .safety
            .pending_tc_high_qc_sync()
            .is_some_and(|pending| pending_tc_contains_qc(pending, &certificate))
        {
            let mut effects = self.try_complete_pending_tc_high_qc_sync(verifier)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        if self.safety.pending_tc_high_qc_sync().is_some()
            && self.safety.pending_standalone_qc_sync().is_none()
            && self.qc_is_durably_subsumed(&certificate)?
        {
            // An unrelated historical QC must not become a new standalone
            // obligation merely because a different TC obligation is active.
            return Ok(side_effects);
        }

        if self.safety.pending_standalone_qc_sync().is_some() {
            let names_active = self
                .safety
                .pending_standalone_qc_sync()
                .is_some_and(|pending| same_qc_coordinates(pending.active(), &certificate));
            if names_active && self.qc_is_ready_for_adoption(&certificate)? {
                let mut effects = self.try_complete_pending_standalone_qc_sync(verifier)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
            if !names_active && self.qc_is_durably_subsumed(&certificate)? {
                return Ok(side_effects);
            }
            if self.remember_pending_standalone_qc(certificate)? {
                let deferred = if self.safety.pending_tc_high_qc_sync().is_some() {
                    vec![DeferredEffect::RequestTcHighQcSync]
                } else {
                    vec![DeferredEffect::RequestStandaloneQcSync]
                };
                let mut effects = self.persist(deferred)?;
                effects.extend(side_effects);
                return Ok(effects);
            }
            let request = if self.safety.pending_tc_high_qc_sync().is_some() {
                self.tc_high_qc_sync_effect()?
            } else {
                self.standalone_qc_sync_effect()?
            };
            side_effects.push(request);
            return Ok(side_effects);
        }

        let ready = self.qc_is_ready_for_adoption(&certificate)?;
        if !ready || self.safety.pending_tc_high_qc_sync().is_some() {
            self.safety
                .set_pending_standalone_qc_sync(Some(PendingStandaloneQcSync::new(certificate)));
            let deferred = if self.safety.pending_tc_high_qc_sync().is_some() {
                vec![DeferredEffect::RequestTcHighQcSync]
            } else {
                vec![DeferredEffect::RequestStandaloneQcSync]
            };
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        let before = self.safety.clone();
        self.process_verified_ready_qc(&certificate, verifier)?;
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        }

        if self.safety != before {
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            Ok(effects)
        } else {
            Ok(side_effects)
        }
    }

    /// Applies the complete §6 QC transition for a certificate whose
    /// signatures, block binding, ancestry, and payload are already available.
    /// Persistence is deliberately owned by the caller so a TC can process all
    /// of its referenced QCs and cross one durability boundary.
    fn process_verified_ready_qc<V: SignatureVerifier>(
        &mut self,
        certificate: &QuorumCertificate,
        verifier: &V,
    ) -> Result<()> {
        if self.qc_is_durably_subsumed(certificate)? {
            return Ok(());
        }
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            return Err(CoreError::ConflictingCertificate);
        }
        self.blocks.validate_certificate_binding(certificate)?;
        self.learn_qc(certificate.clone())?;
        self.safety
            .set_current_view(certificate.view().checked_next()?);

        if let Some(proof) = self.blocks.detect_three_chain(
            certificate,
            self.config.validator_set(),
            self.config.consensus_parameters(),
            self.safety.finalized(),
        )? {
            proof.proof().verify(
                self.config.validator_set(),
                None,
                self.config.consensus_parameters(),
                proof.authenticated_parent().timestamp_ms(),
                verifier,
            )?;
            let committed = proof.proof().finalized_block().header();
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
                        let protected = self.protected_blocks();
                        self.blocks.prune_below(
                            committed.height().get(),
                            committed.id(),
                            &protected,
                        );
                        let proof_id = proof.proof_id();
                        self.safety.set_last_finalization(proof);
                        self.safety.set_pending_finalize(Some(proof_id));
                    }
                    Ancestry::Conflicts => return Err(CoreError::ConflictingCertificate),
                    // Recovery deliberately starts with an empty volatile
                    // tree. Withhold finalization until stale verified
                    // proposals/QCs replay the missing ancestry.
                    Ancestry::Unknown => {}
                }
            }
        }
        Ok(())
    }

    fn handle_tc<V: SignatureVerifier>(
        &mut self,
        certificate: TimeoutCertificateV0,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        self.require_epoch(certificate.epoch())?;
        for referenced in certificate.referenced_qcs() {
            self.reject_epoch_anchor(referenced)?;
        }
        certificate.verify(self.config.validator_set(), None, verifier)?;
        let mut side_effects = Vec::new();
        for referenced in certificate.referenced_qcs() {
            if let Some(referenced_qc) = referenced.as_ordinary() {
                for vote in referenced_qc.votes() {
                    if let Some(evidence) = self.observe_vote(vote)? {
                        side_effects.push(Effect::Evidence(evidence));
                    }
                }
                if let Some(halt) = self.observe_qc(referenced_qc)? {
                    let mut effects = self.persist_safety_halt(halt)?;
                    effects.extend(side_effects);
                    return Ok(effects);
                }
            }
        }
        side_effects.extend(
            self.observe_timeout_certificate(&certificate)?
                .into_iter()
                .map(Effect::Evidence),
        );
        if let Some(block_id) = certificate
            .referenced_qcs()
            .iter()
            .filter_map(QcReferenceV0::as_ordinary)
            .find(|referenced| self.payload_is_deterministically_invalid(referenced.block_id()))
            .map(QuorumCertificate::block_id)
        {
            // TC view advancement is independently authenticated and is not
            // rolled back merely because one certified payload violates the
            // execution-validity assumption. Same-view QC conflicts above
            // take precedence because their complete signed witness must be
            // retained before any durable obligation is cleared.
            self.safety
                .set_current_view(certificate.timed_out_view().checked_next()?);
            let halt = SafetyHalt::deterministically_invalid_payload(
                block_id,
                InvalidPayloadReference::TimeoutCertificate(Box::new(certificate)),
            )?;
            let mut effects = self.persist_payload_safety_halt(halt)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        self.handle_authenticated_tc(certificate, verifier, side_effects)
    }

    /// Applies a fully verified and already-observed timeout certificate.
    /// Proposal carriers call this same path after observing their complete
    /// witness, so every referenced ordinary QC and the full TC survive the
    /// same persistence and recovery contract as direct TC ingress.
    fn handle_authenticated_tc<V: SignatureVerifier>(
        &mut self,
        certificate: TimeoutCertificateV0,
        verifier: &V,
        mut side_effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        let before = self.safety.clone();
        let outcome = self.apply_authenticated_tc(&certificate, verifier)?;

        if outcome == AuthenticatedTcOutcome::MissingReferences {
            if self.safety == before {
                side_effects.push(self.tc_high_qc_sync_effect()?);
                return Ok(side_effects);
            }
            let mut deferred = Vec::new();
            if self.safety.current_view() > before.current_view() {
                deferred.push(DeferredEffect::ArmViewTimer);
            }
            deferred.push(DeferredEffect::RequestTcHighQcSync);
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            return Ok(effects);
        }

        if self.safety != before {
            let mut deferred = vec![DeferredEffect::ArmViewTimer];
            if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
                deferred.push(DeferredEffect::Finalize);
            } else if self.safety.pending_standalone_qc_sync().is_some() {
                deferred.push(DeferredEffect::RequestStandaloneQcSync);
            }
            let mut effects = self.persist(deferred)?;
            effects.extend(side_effects);
            Ok(effects)
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            side_effects.push(self.standalone_qc_sync_effect()?);
            Ok(side_effects)
        } else {
            Ok(side_effects)
        }
    }

    /// Runs the authenticated TC state transition without choosing a
    /// persistence boundary. This lets a first-arrival proposal carrier combine
    /// a ready TC transition with dependent-child admission atomically, while
    /// direct ingress and pending-TC recovery persist through the wrapper above.
    fn apply_authenticated_tc<V: SignatureVerifier>(
        &mut self,
        certificate: &TimeoutCertificateV0,
        verifier: &V,
    ) -> Result<AuthenticatedTcOutcome> {
        let pending = PendingTcHighQcSync::from_timeout_certificate(certificate.clone())?;
        if let Some(existing) = self.safety.pending_tc_high_qc_sync() {
            if existing != &pending {
                return Err(CoreError::ConflictingTcHighQcSyncTarget);
            }
        }

        self.safety
            .set_current_view(certificate.timed_out_view().checked_next()?);

        // TC verification learns every referenced ordinary QC, not only the
        // deterministic maximum. Delay all §6 QC processing until every
        // referenced block/witness/payload is ready; otherwise processing only
        // the selected high QC could miss a lock or finality transition carried
        // by a lower-view referenced QC.
        let referenced_qcs = ordinary_qcs_in_processing_order(certificate);
        let Some(staged) = self.stage_tc_referenced_qcs(&referenced_qcs, verifier)? else {
            if self.safety.pending_tc_high_qc_sync().is_none() {
                self.safety.set_pending_tc_high_qc_sync(Some(pending));
            }
            return Ok(AuthenticatedTcOutcome::MissingReferences);
        };
        *self = staged;
        self.safety.set_pending_tc_high_qc_sync(None);
        self.drain_ready_pending_standalone_qcs(verifier)?;
        Ok(AuthenticatedTcOutcome::Complete)
    }

    fn verify_ordinary_qc<V: SignatureVerifier>(
        &self,
        certificate: &QuorumCertificate,
        verifier: &V,
    ) -> Result<()> {
        self.require_epoch(certificate.epoch())?;
        if certificate.view().get() == 0 || certificate.height().get() == 0 {
            return Err(CoreError::InvalidOrdinaryCertificate);
        }
        self.require_pre_checkpoint_height(certificate.height())?;
        certificate.verify(self.config.validator_set(), verifier)?;
        Ok(())
    }

    fn verify_qc_reference<V: SignatureVerifier>(
        &self,
        reference: &QcReferenceV0,
        verifier: &V,
    ) -> Result<()> {
        match reference {
            QcReferenceV0::Ordinary(certificate) => self.verify_ordinary_qc(certificate, verifier),
            QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
                ContextAuthorizedQcV0::Genesis(anchor) => {
                    anchor.matches_trusted_set(self.config.validator_set())?;
                    Ok(())
                }
                ContextAuthorizedQcV0::Epoch(_) => Err(CoreError::UnsupportedEpochAnchor),
            },
        }
    }

    fn qc_is_ready_for_adoption(&self, certificate: &QuorumCertificate) -> Result<bool> {
        if self.qc_is_durably_subsumed(certificate)? {
            return Ok(true);
        }
        let finalized = self.safety.finalized();
        if self.payload_is_deterministically_invalid(certificate.block_id()) {
            return Err(CoreError::ConflictingCertificate);
        }
        match self.blocks.validate_certificate_binding(certificate) {
            Ok(()) => {}
            Err(CoreError::MissingBlock(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        match self.blocks.validated_ancestry(
            certificate.block_id(),
            finalized,
            self.config.max_block_time_step_ms(),
        ) {
            Ancestry::Descends => Ok(true),
            Ancestry::Unknown => Ok(false),
            Ancestry::Conflicts => Err(CoreError::ConflictingCertificate),
        }
    }

    /// A verified QC at or below the irreversible finalized height can no
    /// longer affect high-QC, lock, or finality and its pruned block need not
    /// be reconstructed. Network ingress must observe same-view QC conflicts
    /// before calling this classifier. At the finalized height, a different
    /// block from another view is therefore harmless historical competition,
    /// while the finalized block with mismatched coordinates is malformed.
    fn qc_is_durably_subsumed(&self, certificate: &QuorumCertificate) -> Result<bool> {
        let finalized = self.safety.finalized();
        if certificate.block_id() == finalized.block_id() {
            return if certificate.height() == finalized.height()
                && certificate.view() == finalized.view()
            {
                Ok(true)
            } else {
                Err(CoreError::ConflictingCertificate)
            };
        }
        if certificate.height() <= finalized.height() {
            return Ok(true);
        }
        Ok(false)
    }

    /// Evaluates a complete TC reference table on a private core snapshot.
    ///
    /// Readiness is intentionally re-evaluated after each ascending QC: a
    /// lower-view three-chain may advance finality and thereby make a later
    /// same-height competing QC durably subsumed. If any later reference is
    /// still unavailable, discarding the snapshot prevents partial lock,
    /// finality, or pruning changes from escaping before the full TC can be
    /// processed atomically.
    fn stage_tc_referenced_qcs<V: SignatureVerifier>(
        &self,
        referenced_qcs: &[QuorumCertificate],
        verifier: &V,
    ) -> Result<Option<Self>> {
        let mut staged = self.clone();
        for certificate in referenced_qcs {
            if !staged.qc_is_ready_for_adoption(certificate)? {
                return Ok(None);
            }
            staged.process_verified_ready_qc(certificate, verifier)?;
        }
        Ok(Some(staged))
    }

    fn try_complete_pending_tc_high_qc_sync<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        let Some(pending) = self.safety.pending_tc_high_qc_sync().cloned() else {
            return Ok(Vec::new());
        };
        let referenced_qcs = ordinary_qcs_in_processing_order(pending.timeout_certificate());
        let Some(staged) = self.stage_tc_referenced_qcs(&referenced_qcs, verifier)? else {
            return Ok(vec![self.tc_high_qc_sync_effect()?]);
        };

        let before = self.safety.clone();
        *self = staged;
        self.safety
            .set_current_view(pending.timed_out_view().checked_next()?);
        self.safety.set_pending_tc_high_qc_sync(None);
        self.drain_ready_pending_standalone_qcs(verifier)?;
        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        self.persist(deferred)
    }

    fn remember_pending_standalone_qc(&mut self, certificate: QuorumCertificate) -> Result<bool> {
        let mut pending =
            self.safety
                .pending_standalone_qc_sync()
                .cloned()
                .ok_or(CoreError::InvalidRecovery(
                    "standalone QC backlog has no active target",
                ))?;
        for existing in core::iter::once(pending.active()).chain(pending.backlog()) {
            if same_qc_coordinates(existing, &certificate) {
                return Ok(false);
            }
            if existing.block_id() == certificate.block_id() {
                return Err(CoreError::ConflictingCertificate);
            }
        }
        if pending.backlog().len().saturating_add(1) >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingStandaloneQcs);
        }
        let mut backlog = pending.backlog().to_vec();
        backlog.push(certificate);
        backlog.sort_by_key(qc_order_key);
        pending.set_backlog(backlog);
        self.safety.set_pending_standalone_qc_sync(Some(pending));
        Ok(true)
    }

    fn try_complete_pending_standalone_qc_sync<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<Vec<Effect>> {
        if self.safety.pending_tc_high_qc_sync().is_some() {
            return Ok(vec![self.tc_high_qc_sync_effect()?]);
        }
        if self.safety.pending_standalone_qc_sync().is_none() {
            return Ok(Vec::new());
        }

        let before = self.safety.clone();
        if !self.drain_ready_pending_standalone_qcs(verifier)? {
            return Ok(vec![self.standalone_qc_sync_effect()?]);
        }

        let mut deferred = vec![DeferredEffect::ArmViewTimer];
        if self.safety.pending_finalize().is_some() && before.pending_finalize().is_none() {
            deferred.push(DeferredEffect::Finalize);
        } else if self.safety.pending_standalone_qc_sync().is_some() {
            deferred.push(DeferredEffect::RequestStandaloneQcSync);
        }
        self.persist(deferred)
    }

    /// Atomically normalizes every standalone target that no longer needs an
    /// external replay. A TC or another ready certificate path may have made
    /// several queued QCs locally processable, and a finality advance may have
    /// subsumed entries anywhere in the queue. Draining the maximal ready
    /// prefix here prevents an already-local or below-finality target from
    /// producing an empty replay followed by the identical request forever.
    fn drain_ready_pending_standalone_qcs<V: SignatureVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<bool> {
        let mut changed = self.discard_durably_subsumed_standalone_qcs()?;
        while let Some(pending) = self.safety.pending_standalone_qc_sync().cloned() {
            if !self.qc_is_ready_for_adoption(pending.active())? {
                break;
            }

            self.process_verified_ready_qc(pending.active(), verifier)?;
            let mut backlog = pending.backlog().to_vec();
            if backlog.is_empty() {
                self.safety.set_pending_standalone_qc_sync(None);
            } else {
                let next = backlog.remove(0);
                self.safety.set_pending_standalone_qc_sync(Some(
                    PendingStandaloneQcSync::from_persisted_parts(next, backlog),
                ));
            }
            changed = true;
            changed |= self.discard_durably_subsumed_standalone_qcs()?;
        }
        Ok(changed)
    }

    fn discard_durably_subsumed_standalone_qcs(&mut self) -> Result<bool> {
        let Some(pending) = self.safety.pending_standalone_qc_sync().cloned() else {
            return Ok(false);
        };
        let mut retained = Vec::new();
        for certificate in
            core::iter::once(pending.active().clone()).chain(pending.backlog().iter().cloned())
        {
            if !self.qc_is_durably_subsumed(&certificate)? {
                retained.push(certificate);
            }
        }
        if retained.len() == pending.backlog().len().saturating_add(1) {
            return Ok(false);
        }
        if retained.is_empty() {
            self.safety.set_pending_standalone_qc_sync(None);
        } else {
            let active = retained.remove(0);
            self.safety.set_pending_standalone_qc_sync(Some(
                PendingStandaloneQcSync::from_persisted_parts(active, retained),
            ));
        }
        Ok(true)
    }

    fn register_validation(&mut self, proposal: &SignedProposalV0) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_validations, proposal) {
            return Ok((id, false));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.insert_payload_validation_obligation(
            PayloadValidationRouteV0::Proposal,
            id,
            proposal,
        )?;
        self.pending_validations.insert(id, proposal.clone());
        Ok((id, true))
    }

    fn payload_validation_completion(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Option<&DurablePayloadValidationCompletionV0> {
        let key = (route, id);
        self.safety
            .payload_validation_completions()
            .binary_search_by_key(&key, DurablePayloadValidationCompletionV0::key)
            .ok()
            .map(|index| &self.safety.payload_validation_completions()[index])
    }

    fn record_payload_validation_completion(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let durable_result = DurablePayloadValidationResultV1::from_live(result);
        for previous in self
            .safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == id.block_id())
        {
            if matches!(
                (previous.result(), durable_result),
                (
                    DurablePayloadValidationResultV1::Valid { commitments: first },
                    DurablePayloadValidationResultV1::Valid {
                        commitments: second
                    }
                ) if first != second
            ) {
                return Err(CoreError::ConflictingPayloadValidation(id.block_id()));
            }
        }
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .any(|completion| completion.id() == id)
        {
            return Err(CoreError::InvalidRecovery(
                "payload validation completion was duplicated or reused across routes",
            ));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "payload validation completion has no pre-reserved durable slot",
            ));
        }
        let key = (route, id);
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation completion revision",
                ))?;
        let mut completions = self.safety.payload_validation_completions().to_vec();
        let index = completions
            .binary_search_by_key(&key, DurablePayloadValidationCompletionV0::key)
            .unwrap_or_else(|index| index);
        completions.insert(
            index,
            DurablePayloadValidationCompletionV0::new(
                route,
                id,
                durable_result,
                first_recorded_revision,
            ),
        );
        self.safety.set_payload_validation_completions(completions);
        Ok(())
    }

    fn record_payload_terminal_fact(
        &mut self,
        block_id: BlockId,
        result: PayloadValidationResult,
    ) -> Result<TerminalFactTransition> {
        let terminal = match result {
            PayloadValidationResult::Valid { .. } => PayloadTerminalResult::Valid,
            PayloadValidationResult::DeterministicallyInvalid => {
                PayloadTerminalResult::DeterministicallyInvalid
            }
            PayloadValidationResult::Unavailable => {
                return Ok(TerminalFactTransition::NotTerminal);
            }
        };
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .filter(|completion| completion.id().block_id() == block_id)
            .filter_map(|completion| match completion.result() {
                DurablePayloadValidationResultV1::Valid { .. } => {
                    Some(PayloadTerminalResult::Valid)
                }
                DurablePayloadValidationResultV1::DeterministicallyInvalid => {
                    Some(PayloadTerminalResult::DeterministicallyInvalid)
                }
                DurablePayloadValidationResultV1::Unavailable => None,
            })
            .any(|previous| previous != terminal)
        {
            return Ok(TerminalFactTransition::Conflicting);
        }
        let mut facts = self.safety.payload_terminal_facts().to_vec();
        match facts.binary_search_by_key(&block_id, |fact| fact.block_id()) {
            Ok(index) if facts[index].result() == terminal => {
                return Ok(TerminalFactTransition::Repeated);
            }
            Ok(_) => return Ok(TerminalFactTransition::Conflicting),
            Err(_) => {}
        }

        let maximum = self.config.max_observed_messages();
        if facts.len() >= maximum {
            // Prefer forgetting an uncertified/non-anchor cache entry. This
            // keeps every currently safety-relevant fact stable across ordinary
            // block-tree eviction while preserving a strict durable bound.
            let protected = durable_payload_fact_blocks(&self.safety);
            let victim = facts
                .iter()
                .enumerate()
                .filter(|(_, fact)| !protected.contains(&fact.block_id()))
                .min_by_key(|(_, fact)| (fact.first_recorded_revision(), fact.block_id()))
                .map(|(index, _)| index)
                .ok_or(CoreError::PayloadTerminalFactCacheFull)?;
            facts.remove(victim);
        }
        let index = facts
            .binary_search_by_key(&block_id, |fact| fact.block_id())
            .unwrap_or_else(|index| index);
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload terminal fact revision",
                ))?;
        facts.insert(
            index,
            PayloadTerminalFact::new(block_id, terminal, first_recorded_revision),
        );
        self.safety.set_payload_terminal_facts(facts);
        Ok(TerminalFactTransition::Inserted)
    }

    fn restore_durable_payload_fact(&mut self, block_id: BlockId) -> Result<()> {
        let Some(result) = self.safety.payload_terminal_result(block_id) else {
            return Ok(());
        };
        let result = match result {
            // A durable Valid fact detects cross-restart terminal conflicts,
            // but the current schema does not retain the canonical body,
            // authenticated parent state, or frozen runtime handle. A newly
            // sourced body must therefore cross the host boundary again before
            // the volatile tree becomes vote-ready.
            PayloadTerminalResult::Valid => return Ok(()),
            PayloadTerminalResult::DeterministicallyInvalid => {
                PayloadValidationResult::DeterministicallyInvalid
            }
        };
        if self.blocks.record_payload_validation(block_id, result)?
            == PayloadTransition::ConflictingTerminalResult
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload fact conflicts with the volatile block tree",
            ));
        }
        Ok(())
    }

    fn payload_is_deterministically_invalid(&self, block_id: BlockId) -> bool {
        self.safety.payload_terminal_result(block_id)
            == Some(PayloadTerminalResult::DeterministicallyInvalid)
            || self.blocks.payload_is_invalid(block_id)
    }

    fn handle_resolved_validation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<Option<Vec<Effect>>> {
        if self
            .safety
            .payload_validation_completions()
            .iter()
            .any(|completion| completion.id() == id && completion.route() != route)
        {
            return Err(CoreError::InvalidRecovery(
                "payload validation callback route differs from its durable completion",
            ));
        }
        let Some(previous) = self
            .payload_validation_completion(route, id)
            .map(DurablePayloadValidationCompletionV0::result)
        else {
            return Ok(None);
        };
        if previous.matches_live(result) {
            return Ok(Some(Vec::new()));
        }
        let terminal_conflict = matches!(
            (previous, result),
            (
                DurablePayloadValidationResultV1::Valid { .. },
                PayloadValidationResult::DeterministicallyInvalid
            ) | (
                DurablePayloadValidationResultV1::DeterministicallyInvalid,
                PayloadValidationResult::Valid { .. }
            )
        );
        if terminal_conflict {
            return self
                .persist_payload_safety_halt(SafetyHalt::conflicting_payload_validation(
                    id.block_id(),
                ))
                .map(Some);
        }
        Err(CoreError::ConflictingPayloadValidation(id.block_id()))
    }

    fn validate_payload_capability(
        id: ValidationId,
        result: PayloadValidationResult,
    ) -> Result<()> {
        let Some(commitments) = result.commitments() else {
            return Ok(());
        };
        if commitments.block_id() != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: id.block_id(),
                received: commitments.block_id(),
            });
        }
        Ok(())
    }

    fn validate_durable_payload_completion(
        id: ValidationId,
        result: DurablePayloadValidationResultV1,
    ) -> Result<()> {
        let Some(commitments) = result.commitments() else {
            return Ok(());
        };
        if commitments.block_id() != id.block_id() {
            return Err(CoreError::ValidationCapabilityMismatch {
                expected: id.block_id(),
                received: commitments.block_id(),
            });
        }
        Ok(())
    }

    fn register_sync_validation(
        &mut self,
        proposal: &SignedProposalV0,
    ) -> Result<(ValidationId, bool)> {
        if let Some(id) = pending_validation_id(&self.pending_sync_validations, proposal) {
            return Ok((id, false));
        }
        if self.payload_validation_slot_count()? >= self.config.max_observed_messages() {
            return Err(CoreError::TooManyPendingValidations);
        }
        let id = self.next_validation_id(proposal)?;
        self.insert_payload_validation_obligation(PayloadValidationRouteV0::Synced, id, proposal)?;
        self.pending_sync_validations.insert(id, proposal.clone());
        Ok((id, true))
    }

    fn next_validation_id(&mut self, proposal: &SignedProposalV0) -> Result<ValidationId> {
        self.next_validation_generation =
            core::cmp::max(self.next_validation_generation, self.safety.revision())
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow("validation generation"))?;
        Ok(ValidationId::new(
            proposal.block().id(),
            proposal.block().header().view(),
            self.next_validation_generation,
        ))
    }

    fn insert_payload_validation_obligation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let parent = self.payload_validation_parent(id, proposal.block())?;
        let first_recorded_revision =
            self.safety
                .revision()
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation obligation revision",
                ))?;
        let obligation = DurablePayloadValidationObligationV0::new(
            route,
            id,
            proposal.clone(),
            parent,
            first_recorded_revision,
        );
        let mut obligations = self.safety.payload_validation_obligations().to_vec();
        let aggregate_resource_size = obligations
            .iter()
            .chain(core::iter::once(&obligation))
            .try_fold(0usize, |aggregate, obligation| {
                aggregate
                    .checked_add(Self::payload_validation_obligation_resource_size_v0(
                        obligation,
                    )?)
                    .ok_or(CoreError::ArithmeticOverflow(
                        "payload validation obligation resource bytes",
                    ))
            })?;
        let maximum = self
            .config
            .consensus_parameters()
            .max_consensus_message_bytes() as usize;
        if aggregate_resource_size > maximum {
            return Err(CoreError::PayloadValidationResourceTooLarge {
                actual: aggregate_resource_size,
                maximum,
            });
        }
        let index =
            match obligations.binary_search_by_key(&id, DurablePayloadValidationObligationV0::id) {
                Ok(_) => {
                    return Err(CoreError::InvalidRecovery(
                        "payload validation obligation was duplicated",
                    ));
                }
                Err(index) => index,
            };
        obligations.insert(index, obligation);
        self.safety.set_payload_validation_obligations(obligations);
        Ok(())
    }

    /// Computes one deterministic, process-local resource weight for the
    /// complete durable obligation. This is not a wire encoding or a new
    /// consensus-validity size: the fixed frames merely ensure that every
    /// retained authority-bearing field contributes to the bounded
    /// SafetyState footprint.
    fn payload_validation_obligation_resource_size_v0(
        obligation: &DurablePayloadValidationObligationV0,
    ) -> Result<usize> {
        // route u8 + ValidationId (BlockId + view + generation) + proposal
        // frame + parent tip (height + view + BlockId + timestamp) + exact
        // header presence + first-recorded revision.
        const FIXED_BYTES: usize = 1 + (32 + 8 + 8) + 4 + (8 + 8 + 32 + 8) + 1 + 8;
        let mut size = obligation
            .proposal()
            .durable_validation_resource_size_v0()?
            .checked_add(FIXED_BYTES)
            .ok_or(CoreError::ArithmeticOverflow(
                "payload validation obligation resource bytes",
            ))?;
        if let Some(header) = obligation.parent().exact_header() {
            let header_size = header.try_cev0_bytes()?.len();
            size = size
                .checked_add(4)
                .and_then(|size| size.checked_add(header_size))
                .ok_or(CoreError::ArithmeticOverflow(
                    "payload validation obligation parent header bytes",
                ))?;
        }
        Ok(size)
    }

    fn require_payload_validation_obligation(
        &self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: &SignedProposalV0,
    ) -> Result<()> {
        let obligations = self.safety.payload_validation_obligations();
        let index = obligations
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .map_err(|_| {
                CoreError::InvalidRecovery(
                    "a volatile payload validation has no durable obligation",
                )
            })?;
        let obligation = &obligations[index];
        if obligation.route() != route || obligation.proposal() != proposal {
            return Err(CoreError::InvalidRecovery(
                "a payload validation callback differs from its durable route or proposal",
            ));
        }
        Ok(())
    }

    fn remove_payload_validation_obligation(
        &mut self,
        route: PayloadValidationRouteV0,
        id: ValidationId,
    ) -> Result<()> {
        let mut obligations = self.safety.payload_validation_obligations().to_vec();
        let index = obligations
            .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
            .map_err(|_| {
                CoreError::InvalidRecovery("payload validation cleanup has no durable obligation")
            })?;
        if obligations[index].route() != route {
            return Err(CoreError::InvalidRecovery(
                "payload validation cleanup used the wrong durable route",
            ));
        }
        obligations.remove(index);
        self.safety.set_payload_validation_obligations(obligations);
        Ok(())
    }

    fn ensure_payload_validation_cleanup_barrier(
        &mut self,
        effects: Vec<Effect>,
    ) -> Result<Vec<Effect>> {
        if let Some(pending) = &self.pending_persistence {
            return match effects.as_slice() {
                [Effect::PersistSafetyState { barrier, state }]
                    if *barrier == pending.barrier && state.as_ref() == &self.safety =>
                {
                    Ok(effects)
                }
                _ => Err(CoreError::InvalidRecovery(
                    "payload validation cleanup exposed a non-persistence effect beside an active barrier",
                )),
            };
        }
        let mut deferred = Vec::with_capacity(effects.len());
        for effect in effects {
            match effect {
                Effect::RequestTcHighQcSync { .. } => {
                    deferred.push(DeferredEffect::RequestTcHighQcSync);
                }
                Effect::RequestStandaloneQcSync { .. } => {
                    deferred.push(DeferredEffect::RequestStandaloneQcSync);
                }
                _ => {
                    return Err(CoreError::InvalidRecovery(
                        "payload validation cleanup exposed an effect before persistence",
                    ));
                }
            }
        }
        self.persist(deferred)
    }

    fn observe_proposal(
        &mut self,
        proposal: &SignedProposalV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<Option<EquivocationEvidence>> {
        let header = proposal.block().header();
        let key = (header.epoch(), header.view(), proposal.proposer());
        if let Some(first) = self.observed_proposals.get(&key).cloned() {
            if first.proposal.conflicts_with(proposal) {
                return Ok(Some(EquivocationEvidence::proposal(
                    first.proposal,
                    proposal.clone(),
                    self.config.validator_set(),
                    None,
                    self.config.consensus_parameters(),
                    first.authenticated_parent_timestamp_ms,
                    authenticated_parent_timestamp_ms,
                )?));
            }
            return Ok(None);
        }
        bounded_insert(
            &mut self.observed_proposals,
            key,
            ObservedProposal {
                proposal: proposal.clone(),
                authenticated_parent_timestamp_ms,
            },
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

    fn observe_timeout_certificate(
        &mut self,
        certificate: &TimeoutCertificateV0,
    ) -> Result<Vec<EquivocationEvidence>> {
        let mut evidence = Vec::new();
        for entry in certificate.entries() {
            let vote = TimeoutVote::new(
                certificate.chain_id(),
                certificate.protocol_version(),
                certificate.epoch(),
                certificate.timed_out_view(),
                certificate.validator_set_hash(),
                entry.high_qc(),
                entry.signer_id(),
                *entry.signature(),
                self.config.validator_set(),
            )?;
            if let Some(conflict) = self.observe_timeout(&vote)? {
                evidence.push(conflict);
            }
        }
        Ok(evidence)
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
            if self.payload_is_deterministically_invalid(certificate.block_id()) {
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
            self.reject_epoch_anchor(&justify)?;
            let justify_ref = justify.qc_ref();
            let locked_ref = self.safety.locked_qc().qc_ref();
            if justify_ref.view() == locked_ref.view()
                && justify_ref.block_id() != locked_ref.block_id()
            {
                return Err(CoreError::ConflictingCertificate);
            }
            if qc_order_key_ref(&justify) > qc_order_key_ref(self.safety.locked_qc()) {
                self.safety.set_locked_qc(justify);
            }
        }
        self.adopt_high_qc(certificate)
    }

    fn adopt_high_qc(&mut self, certificate: QuorumCertificate) -> Result<()> {
        self.require_descendant_of_finalized(&certificate)?;
        let current = self.safety.high_qc();
        let candidate = QcReferenceV0::ordinary(certificate);
        let candidate_ref = candidate.qc_ref();
        let current_ref = current.qc_ref();
        if candidate_ref.view() == current_ref.view()
            && candidate_ref.block_id() != current_ref.block_id()
        {
            return Err(CoreError::ConflictingCertificate);
        }
        if qc_order_key_ref(&candidate) > qc_order_key_ref(current) {
            self.safety.set_high_qc(candidate);
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

    fn durable_qc_references(&self) -> Vec<&QcReferenceV0> {
        let mut references = vec![self.safety.high_qc(), self.safety.locked_qc()];
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            references.extend(pending.timeout_certificate().referenced_qcs());
        }
        if let Some(proof) = self.safety.last_finalization_proof() {
            for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
                references.push(certified.justify_qc());
                if let Some(timeout) = certified.timeout_certificate() {
                    references.extend(timeout.referenced_qcs());
                }
            }
        }
        references
    }

    fn durable_qcs(&self) -> Vec<&QuorumCertificate> {
        let mut certificates = Vec::new();
        certificates.extend(
            [self.safety.high_qc(), self.safety.locked_qc()]
                .into_iter()
                .filter_map(QcReferenceV0::as_ordinary),
        );
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            certificates.extend(
                pending
                    .timeout_certificate()
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary),
            );
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            certificates.extend(core::iter::once(pending.active()).chain(pending.backlog()));
        }
        if let Some(proof) = self.safety.last_finalization_proof() {
            for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
                certificates.push(certified.certifying_qc());
                if let Some(justify) = certified.justify_qc().as_ordinary() {
                    certificates.push(justify);
                }
                if let Some(timeout) = certified.timeout_certificate() {
                    certificates.extend(
                        timeout
                            .referenced_qcs()
                            .iter()
                            .filter_map(QcReferenceV0::as_ordinary),
                    );
                }
            }
        }
        certificates
    }

    /// Returns the strongest independently recoverable reference which names
    /// `block_id`. Volatile QCs are copied into the durable halt diagnostic so
    /// recovery never depends on the observation cache which saw them.
    fn invalid_payload_reference(&self, block_id: BlockId) -> Option<InvalidPayloadReference> {
        if let Some(certificate) = self
            .safety
            .pending_tc_high_qc_sync()
            .map(PendingTcHighQcSync::timeout_certificate)
            .filter(|certificate| {
                certificate
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| referenced.block_id() == block_id)
            })
        {
            return Some(InvalidPayloadReference::TimeoutCertificate(Box::new(
                certificate.clone(),
            )));
        }
        let certificate = self
            .durable_qcs()
            .into_iter()
            .chain(self.observed_qcs.values())
            .filter(|certificate| certificate.block_id() == block_id)
            .min_by_key(|certificate| qc_order_key(certificate))
            .cloned();
        if let Some(certificate) = certificate {
            return Some(InvalidPayloadReference::QuorumCertificate(Box::new(
                certificate,
            )));
        }
        match self.safety.pending_sign() {
            Some(
                intent @ SignIntent::Vote {
                    block_id: pending_block,
                    ..
                },
            ) if *pending_block == block_id => Some(InvalidPayloadReference::PendingVote(
                Box::new(intent.clone()),
            )),
            Some(SignIntent::Vote { .. }) | Some(SignIntent::TimeoutVote { .. }) | None => None,
        }
    }

    fn persist_certified_invalid_payload(
        &mut self,
        certificate: QuorumCertificate,
    ) -> Result<Vec<Effect>> {
        let block_id = certificate.block_id();
        let halt = SafetyHalt::deterministically_invalid_payload(
            block_id,
            InvalidPayloadReference::QuorumCertificate(Box::new(certificate)),
        )?;
        self.persist_payload_safety_halt(halt)
    }

    fn persist_proposal_invalid_payload(
        &mut self,
        proposal: &SignedProposalV0,
        certificate: QuorumCertificate,
    ) -> Result<Vec<Effect>> {
        let block_id = certificate.block_id();
        if let Some(timeout) = proposal
            .witness()
            .timeout_certificate()
            .filter(|timeout| {
                timeout
                    .referenced_qcs()
                    .iter()
                    .filter_map(QcReferenceV0::as_ordinary)
                    .any(|referenced| referenced.block_id() == block_id)
            })
            .cloned()
        {
            self.safety
                .set_current_view(timeout.timed_out_view().checked_next()?);
            let halt = SafetyHalt::deterministically_invalid_payload(
                block_id,
                InvalidPayloadReference::TimeoutCertificate(Box::new(timeout)),
            )?;
            return self.persist_payload_safety_halt(halt);
        }
        self.persist_certified_invalid_payload(certificate)
    }

    /// Cancels all dependent durable/volatile outboxes and crosses exactly one
    /// persistence barrier before exposing `SafetyHalted`. A late signer or
    /// application acknowledgement is subsequently rejected by the halt gate.
    fn persist_payload_safety_halt(&mut self, halt: SafetyHalt) -> Result<Vec<Effect>> {
        self.persist_safety_halt(halt)
    }

    fn persist_safety_halt(&mut self, halt: SafetyHalt) -> Result<Vec<Effect>> {
        self.safety.set_pending_sign(None);
        self.safety.set_pending_finalize(None);
        self.safety.set_pending_tc_high_qc_sync(None);
        self.safety.set_pending_standalone_qc_sync(None);
        self.safety.set_safety_halt(Some(halt));
        self.awaiting_signature = false;
        self.replay_required = false;
        self.finalization_blocked_vote = None;
        self.pending_validations.clear();
        self.pending_sync_validations.clear();
        self.safety.set_payload_validation_obligations(Vec::new());
        self.persist(vec![DeferredEffect::SafetyHalted])
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

    fn signature_effect(&self, intent: &SignIntent) -> Result<Effect> {
        self.require_supported_sign_intent(intent)?;
        Ok(Effect::RequestSignature {
            id: intent.id(),
            author: self.config.local_validator(),
            kind: intent.kind(),
            signing_root: intent.signing_root(),
        })
    }

    fn tc_high_qc_sync_effect(&self) -> Result<Effect> {
        let pending = self
            .safety
            .pending_tc_high_qc_sync()
            .ok_or(CoreError::InvalidRecovery(
                "TC high-QC sync effect has no durable target",
            ))?;
        let mut target = None;
        for certificate in ordinary_qcs_in_processing_order(pending.timeout_certificate()) {
            if !self.qc_is_ready_for_adoption(&certificate)? {
                target = Some(QcRef::from(&certificate));
                break;
            }
        }
        let target = target.ok_or(CoreError::InvalidRecovery(
            "TC QC sync effect has no unready referenced QC",
        ))?;
        Ok(Effect::RequestTcHighQcSync {
            certificate_id: pending.certificate_id(),
            timed_out_view: pending.timed_out_view(),
            target,
            finalized: self.safety.finalized(),
        })
    }

    fn standalone_qc_sync_effect(&self) -> Result<Effect> {
        let pending =
            self.safety
                .pending_standalone_qc_sync()
                .ok_or(CoreError::InvalidRecovery(
                    "standalone QC sync effect has no durable target",
                ))?;
        Ok(Effect::RequestStandaloneQcSync {
            certificate_id: pending.active().id(),
            target: QcRef::from(pending.active()),
            finalized: self.safety.finalized(),
        })
    }

    fn finalize_effect(&self, proof_id: CertificateId) -> Result<Effect> {
        let durable = self
            .safety
            .last_finalization()
            .ok_or(CoreError::UnexpectedFinalizationAck)?;
        if durable.proof_id() != proof_id || self.safety.pending_finalize() != Some(proof_id) {
            return Err(CoreError::UnexpectedFinalizationAck);
        }
        Ok(Effect::Finalize(Box::new(durable.proof().clone())))
    }

    fn protected_blocks(&self) -> Vec<trnm_consensus_types::BlockId> {
        let mut protected = vec![
            self.safety.high_qc().qc_ref().block_id(),
            self.safety.locked_qc().qc_ref().block_id(),
            self.safety.finalized().block_id(),
        ];
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            protected.extend(
                pending
                    .timeout_certificate()
                    .referenced_qcs()
                    .iter()
                    .map(|reference| reference.qc_ref().block_id()),
            );
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            protected.extend(
                core::iter::once(pending.active())
                    .chain(pending.backlog())
                    .map(QuorumCertificate::block_id),
            );
        }
        if let Some(proof) = self.safety.last_finalization_proof() {
            protected.extend([
                proof.finalized_block().header().id(),
                proof.child().header().id(),
                proof.grandchild().header().id(),
            ]);
        }
        if let Some(SignIntent::Vote { block_id, .. }) = self.safety.pending_sign() {
            protected.push(*block_id);
        }
        if let Some(proposal) = &self.finalization_blocked_vote {
            protected.push(proposal.block().id());
        }
        if let Some(block_id) = self
            .safety
            .safety_halt()
            .and_then(SafetyHalt::payload_block_id)
        {
            protected.push(block_id);
        }
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
            self.safety.high_qc().qc_ref().height().get(),
            self.safety.locked_qc().qc_ref().height().get(),
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

    fn active_epoch_geometry(&self) -> Result<EpochGeometryV0> {
        Ok(EpochGeometryV0::new(
            self.safety.epoch(),
            self.config.consensus_parameters(),
        )?)
    }

    /// The current core implements only the ordinary pre-checkpoint segment
    /// of epoch zero. Checkpoint, seal, and handoff authorization must remain
    /// unreachable until the full transition preimage and ancestry proof are
    /// authenticated atomically.
    fn require_pre_checkpoint_height(&self, height: Height) -> Result<()> {
        let checkpoint_height = self.active_epoch_geometry()?.checkpoint_height();
        if height >= checkpoint_height {
            return Err(CoreError::EpochBoundaryUnsupported {
                height,
                checkpoint_height,
            });
        }
        Ok(())
    }

    fn require_supported_proposal_header(&self, header: &BlockHeader) -> Result<()> {
        self.require_epoch(header.epoch())?;
        // Preserve the existing fail-closed classification for every
        // non-regular block kind. A regular header still cannot cross into the
        // heights reserved for the epoch-transition protocol.
        if header.block_kind() != BlockKind::Regular {
            return Err(CoreError::UnsupportedBlockKind);
        }
        self.require_pre_checkpoint_height(header.height())
    }

    fn require_supported_sign_intent(&self, intent: &SignIntent) -> Result<()> {
        match intent {
            SignIntent::Vote { height, .. } => self.require_pre_checkpoint_height(*height),
            SignIntent::TimeoutVote { high_qc, .. } => {
                self.require_pre_checkpoint_height(high_qc.height())
            }
        }
    }

    fn validate_epoch_boundary_fence(&self) -> Result<()> {
        self.require_pre_checkpoint_height(self.safety.finalized().height())?;

        // Include synthetic references here as well as the ordinary QCs below
        // so a decoded high/lock/finality record cannot evade the height fence
        // merely by changing its authorization variant.
        for reference in self.durable_qc_references() {
            self.require_pre_checkpoint_height(reference.qc_ref().height())?;
        }
        for certificate in self.durable_qcs() {
            self.require_pre_checkpoint_height(certificate.height())?;
        }

        if let Some(intent) = self.safety.pending_sign() {
            self.require_supported_sign_intent(intent)?;
        }
        if let Some(halt) = self.safety.safety_halt() {
            match halt {
                SafetyHalt::ConflictingQuorumCertificates { first, second } => {
                    self.require_pre_checkpoint_height(first.height())?;
                    self.require_pre_checkpoint_height(second.height())?;
                }
                SafetyHalt::ConflictingPayloadValidation { .. } => {}
                SafetyHalt::DeterministicallyInvalidPayload { reference, .. } => match reference {
                    InvalidPayloadReference::QuorumCertificate(certificate) => {
                        self.require_pre_checkpoint_height(certificate.height())?;
                    }
                    InvalidPayloadReference::TimeoutCertificate(certificate) => {
                        self.require_epoch(certificate.epoch())?;
                        for referenced in certificate.referenced_qcs() {
                            self.reject_epoch_anchor(referenced)?;
                        }
                    }
                    InvalidPayloadReference::PendingVote(intent) => {
                        self.require_supported_sign_intent(intent)?;
                    }
                },
            }
        }
        Ok(())
    }

    fn validate_payload_validation_obligations<V: SignatureVerifier>(
        &self,
        verifier: &V,
        verify_durable_crypto: bool,
    ) -> Result<()> {
        let obligations = self.safety.payload_validation_obligations();
        if obligations.len() > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations exceed the configured bound",
            ));
        }
        if obligations
            .windows(2)
            .any(|pair| pair[0].id() >= pair[1].id())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation obligations are not uniquely sorted by full id",
            ));
        }

        let mut aggregate_resource_bytes = 0usize;
        for obligation in obligations {
            let id = obligation.id();
            let proposal = obligation.proposal();
            let block = proposal.block();
            let header = block.header();
            if id.block_id() != block.id() || id.view() != header.view() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation id differs from its signed proposal",
                ));
            }
            if obligation.first_recorded_revision() == 0
                || obligation.first_recorded_revision() > self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation has an impossible first revision",
                ));
            }
            if id.generation() != obligation.first_recorded_revision() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation generation differs from its first revision",
                ));
            }
            if block.logical_block_size() > self.config.max_block_bytes() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation exceeds max block bytes",
                ));
            }
            aggregate_resource_bytes = aggregate_resource_bytes
                .checked_add(Self::payload_validation_obligation_resource_size_v0(
                    obligation,
                )?)
                .ok_or(CoreError::InvalidRecovery(
                    "durable payload validation obligation resource bytes overflow",
                ))?;
            if aggregate_resource_bytes
                > self
                    .config
                    .consensus_parameters()
                    .max_consensus_message_bytes() as usize
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation obligation resources exceed the bounded SafetyState budget",
                ));
            }

            self.require_supported_proposal_header(header)?;
            let parent = obligation.parent();
            let tip = parent.tip();
            if header.parent_id() != tip.block_id()
                || header.height() != tip.height().checked_next()?
                || header.genesis_hash() != self.config.validator_set().genesis_hash()
                || header.chain_id() != self.config.validator_set().chain_id()
                || header.protocol_version() != self.config.validator_set().protocol_version()
                || header.epoch() != self.config.validator_set().epoch()
                || header.validator_set_id() != self.config.validator_set().id()
                || header.consensus_parameters_hash() != self.config.consensus_parameters().hash()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation target differs from its authenticated context",
                ));
            }
            match parent.exact_header() {
                Some(exact)
                    if exact.id() == tip.block_id()
                        && exact.height() == tip.height()
                        && exact.view() == tip.view()
                        && exact.timestamp_ms() == tip.timestamp_ms()
                        && payload_parent_context_matches_target_v0(header, exact)? => {}
                Some(_) => {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation exact parent is inconsistent",
                    ));
                }
                None if tip.height().get() == 0
                    && tip.view().get() == 0
                    && tip.block_id() == self.config.genesis_block_id()
                    && tip.timestamp_ms() == self.config.trusted_genesis_timestamp_ms() => {}
                None => {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation lacks a non-genesis parent header",
                    ));
                }
            }
            if verify_durable_crypto {
                proposal.verify(
                    self.config.validator_set(),
                    None,
                    self.config.consensus_parameters(),
                    tip.timestamp_ms(),
                    verifier,
                )?;
            }
        }

        let volatile_count = self.pending_validation_count();
        // Recovery validates the detached durable record before the explicit
        // nonempty-obligation fail-closed check in `Core::recover`. Every live
        // transition, however, must retain an exact volatile mirror for each
        // durable obligation so an in-process map loss cannot pass unnoticed.
        if !verify_durable_crypto || obligations.is_empty() {
            if volatile_count != obligations.len() {
                return Err(CoreError::InvalidRecovery(
                    "volatile payload validations differ from durable obligations",
                ));
            }
            for obligation in obligations {
                let pending = match obligation.route() {
                    PayloadValidationRouteV0::Proposal => {
                        self.pending_validations.get(&obligation.id())
                    }
                    PayloadValidationRouteV0::Synced => {
                        self.pending_sync_validations.get(&obligation.id())
                    }
                };
                if pending != Some(obligation.proposal()) {
                    return Err(CoreError::InvalidRecovery(
                        "volatile payload validation route or proposal differs from durable obligation",
                    ));
                }
            }
        }
        if self.next_validation_generation
            < obligations
                .iter()
                .map(|obligation| obligation.id().generation())
                .chain(
                    self.safety
                        .payload_validation_completions()
                        .iter()
                        .map(|completion| completion.id().generation()),
                )
                .max()
                .unwrap_or(0)
        {
            return Err(CoreError::InvalidRecovery(
                "validation generation is behind a durable validation record",
            ));
        }
        Ok(())
    }

    fn validate_payload_validation_completions(&self) -> Result<()> {
        let completions = self.safety.payload_validation_completions();
        let durable_slots = self
            .safety
            .payload_validation_obligations()
            .len()
            .checked_add(completions.len())
            .ok_or(CoreError::InvalidRecovery(
                "durable payload validation slot count overflow",
            ))?;
        if durable_slots > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation records exceed the configured bound",
            ));
        }
        if completions
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation completions are not uniquely sorted by route and full id",
            ));
        }

        let mut routes_by_id = BTreeMap::new();
        let mut terminal_results_by_block = BTreeMap::new();
        for completion in completions {
            let id = completion.id();
            Self::validate_durable_payload_completion(id, completion.result()).map_err(|_| {
                CoreError::InvalidRecovery(
                    "durable payload validation completion result differs from its full id",
                )
            })?;
            if id.generation() == 0
                || completion.first_recorded_revision() == 0
                || id.generation() > completion.first_recorded_revision()
                || completion.first_recorded_revision() > self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion has an impossible generation or first revision",
                ));
            }
            if routes_by_id.insert(id, completion.route()).is_some() {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion reused one full id across routes",
                ));
            }
            if self
                .safety
                .payload_validation_obligations()
                .binary_search_by_key(&id, DurablePayloadValidationObligationV0::id)
                .is_ok()
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion overlaps a live obligation",
                ));
            }
            if completion.result().is_unavailable() {
                continue;
            }
            let completion_terminal = if completion.result().is_valid() {
                PayloadTerminalResult::Valid
            } else {
                PayloadTerminalResult::DeterministicallyInvalid
            };
            let matching_halt = matches!(
                self.safety.safety_halt(),
                Some(SafetyHalt::ConflictingPayloadValidation { block_id, .. })
                    if *block_id == id.block_id()
            );
            if self
                .safety
                .payload_terminal_result(id.block_id())
                .is_some_and(|terminal| terminal != completion_terminal)
                && !matching_halt
            {
                return Err(CoreError::InvalidRecovery(
                    "durable payload validation completion conflicts with its terminal fact",
                ));
            }
            if let Some(previous) =
                terminal_results_by_block.insert(id.block_id(), completion.result())
            {
                let valid_commitment_conflict = matches!(
                    (previous, completion.result()),
                    (
                        DurablePayloadValidationResultV1::Valid { commitments: first },
                        DurablePayloadValidationResultV1::Valid {
                            commitments: second
                        }
                    ) if first != second
                );
                if valid_commitment_conflict {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation completions disagree on valid commitments",
                    ));
                }
                let terminal_conflict = previous.is_valid() != completion.result().is_valid();
                if terminal_conflict && !matching_halt {
                    return Err(CoreError::InvalidRecovery(
                        "conflicting durable payload validation completions lack their exact safety halt",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_runtime<V: SignatureVerifier>(
        &self,
        verifier: &V,
        verify_durable_crypto: bool,
    ) -> Result<()> {
        self.config.validate()?;
        let set = self.config.validator_set();
        if self.safety.schema_version() != SAFETY_STATE_SCHEMA_VERSION {
            return Err(CoreError::InvalidRecovery(
                "unsupported safety-state schema version",
            ));
        }
        self.validate_payload_validation_obligations(verifier, verify_durable_crypto)?;
        self.validate_payload_validation_completions()?;
        if self.safety.payload_terminal_facts().len() > self.config.max_observed_messages() {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal facts exceed the configured bound",
            ));
        }
        if self
            .safety
            .payload_terminal_facts()
            .windows(2)
            .any(|pair| pair[0].block_id() >= pair[1].block_id())
        {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal facts are not uniquely sorted",
            ));
        }
        if self.safety.payload_terminal_facts().iter().any(|fact| {
            fact.first_recorded_revision() == 0
                || fact.first_recorded_revision() > self.safety.revision()
        }) {
            return Err(CoreError::InvalidRecovery(
                "durable payload terminal fact has an impossible first revision",
            ));
        }
        if set.epoch() != Epoch::new(0) {
            return Err(CoreError::InvalidRecovery(
                "epoch transition is not implemented by this core",
            ));
        }
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

        self.validate_epoch_boundary_fence()?;

        // Every durable contextual reference is checked in its own trust
        // domain. Ordinary certificates receive full signature verification;
        // GenesisQC must exactly match the trusted set; EpochAnchorQC remains
        // fail-closed until atomic epoch transition is implemented.
        if verify_durable_crypto {
            for reference in self.durable_qc_references() {
                self.verify_qc_reference(reference, verifier)?;
            }
        }
        if let Some(pending) = self.safety.pending_tc_high_qc_sync() {
            for reference in pending.timeout_certificate().referenced_qcs() {
                self.reject_epoch_anchor(reference)?;
            }
            if verify_durable_crypto {
                pending.timeout_certificate().verify(set, None, verifier)?;
            }
            let reconstructed = PendingTcHighQcSync::from_timeout_certificate(
                pending.timeout_certificate().clone(),
            )?;
            if &reconstructed != pending {
                return Err(CoreError::InvalidRecovery(
                    "pending TC sync target differs from its certificate selection",
                ));
            }
            if pending.selected_high_qc().as_ordinary().is_none() {
                return Err(CoreError::InvalidRecovery(
                    "a synthetic high QC never requires block synchronization",
                ));
            }
            if self.safety.current_view() < pending.timed_out_view().checked_next()? {
                return Err(CoreError::InvalidRecovery(
                    "pending TC sync did not durably advance through the certified timeout view",
                ));
            }
        }
        if let Some(pending) = self.safety.pending_standalone_qc_sync() {
            let certificates: Vec<_> = core::iter::once(pending.active())
                .chain(pending.backlog())
                .collect();
            if certificates.len() > self.config.max_observed_messages() {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync backlog exceeds the configured bound",
                ));
            }
            if pending
                .backlog()
                .windows(2)
                .any(|pair| qc_order_key(&pair[0]) >= qc_order_key(&pair[1]))
            {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync backlog is not canonically sorted",
                ));
            }
            for certificate in &certificates {
                self.require_epoch(certificate.epoch())?;
                if certificate.view().get() == 0 || certificate.height().get() == 0 {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC sync contains an invalid ordinary certificate",
                    ));
                }
                if verify_durable_crypto {
                    self.verify_ordinary_qc(certificate, verifier)?;
                }
            }
            for (index, first) in certificates.iter().enumerate() {
                if certificates
                    .iter()
                    .skip(index + 1)
                    .any(|second| same_qc_coordinates(first, second))
                {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC sync contains duplicate certificate coordinates",
                    ));
                }
            }
        }

        match self.safety.last_finalization() {
            Some(durable) => {
                let reconstructed = crate::DurableFinalizationV0::new(
                    durable.authenticated_parent(),
                    durable.proof().clone(),
                )?;
                if &reconstructed != durable {
                    return Err(CoreError::InvalidRecovery(
                        "durable finalization is not canonically bound to its parent",
                    ));
                }
                if verify_durable_crypto {
                    durable.proof().verify(
                        set,
                        None,
                        self.config.consensus_parameters(),
                        durable.authenticated_parent().timestamp_ms(),
                        verifier,
                    )?;
                }
                let committed = durable.proof().finalized_block().header();
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
                    || self.safety.finalized().timestamp_ms()
                        != self.config.trusted_genesis_timestamp_ms()
                {
                    return Err(CoreError::InvalidRecovery(
                        "a finalization-free state must use the exact trusted genesis tip",
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
                if first.block_id() == second.block_id()
                    && (first.view() != second.view() || first.height() != second.height())
                {
                    return Err(CoreError::InvalidRecovery(
                        "durable QCs assign different coordinates to one block",
                    ));
                }
            }
        }
        for fact in self
            .safety
            .payload_terminal_facts()
            .iter()
            .filter(|fact| fact.result() == PayloadTerminalResult::DeterministicallyInvalid)
        {
            if self.invalid_payload_reference(fact.block_id()).is_some()
                && self
                    .safety
                    .safety_halt()
                    .and_then(SafetyHalt::payload_block_id)
                    != Some(fact.block_id())
            {
                return Err(CoreError::InvalidRecovery(
                    "durable invalid payload collides with an active safety reference without a halt",
                ));
            }
        }

        if let Some(proof) = self.safety.last_finalization_proof() {
            if qc_order_key_ref(self.safety.high_qc())
                < qc_order_key(proof.grandchild().certifying_qc())
            {
                return Err(CoreError::InvalidRecovery(
                    "high QC is behind the permanent finalization proof",
                ));
            }
            if qc_order_key_ref(self.safety.locked_qc())
                < qc_order_key(proof.child().certifying_qc())
            {
                return Err(CoreError::InvalidRecovery(
                    "locked QC is behind the permanent finalization proof",
                ));
            }
        }

        let high = self.safety.high_qc().qc_ref();
        let locked = self.safety.locked_qc().qc_ref();
        let finalized = self.safety.finalized();
        if locked.view() == high.view() && locked.block_id() != high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-view locked and high QCs certify different blocks",
            ));
        }
        if locked.block_id() == high.block_id()
            && (locked.view() != high.view() || locked.height() != high.height())
        {
            return Err(CoreError::InvalidRecovery(
                "locked and high QCs assign different coordinates to one block",
            ));
        }
        if qc_order_key_ref(self.safety.locked_qc()) > qc_order_key_ref(self.safety.high_qc()) {
            return Err(CoreError::InvalidRecovery("locked QC is ahead of high QC"));
        }
        if self.safety.current_view() <= high.view() {
            return Err(CoreError::InvalidRecovery(
                "current view must be ahead of the high QC",
            ));
        }
        if finalized.height() > high.height() || finalized.view() > high.view() {
            return Err(CoreError::InvalidRecovery(
                "finalized tip is ahead of the high QC",
            ));
        }
        if finalized.height() > locked.height() || finalized.view() > locked.view() {
            return Err(CoreError::InvalidRecovery(
                "locked QC is behind the finalized tip",
            ));
        }
        if finalized.height() == high.height() && finalized.block_id() != high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-height finalized tip and high QC identify different blocks",
            ));
        }
        if finalized.height() == locked.height() && finalized.block_id() != locked.block_id() {
            return Err(CoreError::InvalidRecovery(
                "equal-height locked QC conflicts with finalized tip",
            ));
        }
        for reference in [high, locked] {
            if reference.block_id() == finalized.block_id()
                && (reference.height() != finalized.height()
                    || reference.view() != finalized.view())
            {
                return Err(CoreError::InvalidRecovery(
                    "QC coordinates do not match the finalized anchor",
                ));
            }
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
        if self.safety.pending_tc_high_qc_sync().is_some() {
            if self.safety.pending_finalize().is_some() {
                return Err(CoreError::InvalidRecovery(
                    "TC QC sync cannot overlap a finalization outbox",
                ));
            }
            if matches!(self.safety.pending_sign(), Some(SignIntent::Vote { .. })) {
                return Err(CoreError::InvalidRecovery(
                    "TC QC sync cannot overlap a proposal-vote outbox",
                ));
            }
        }
        if self.safety.pending_standalone_qc_sync().is_some()
            && matches!(self.safety.pending_sign(), Some(SignIntent::Vote { .. }))
        {
            return Err(CoreError::InvalidRecovery(
                "standalone QC sync cannot overlap a proposal-vote outbox",
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
                    if *high_qc != self.safety.high_qc().qc_ref() {
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
        if let Some(proof_id) = self.safety.pending_finalize() {
            let durable = self
                .safety
                .last_finalization()
                .ok_or(CoreError::InvalidRecovery(
                    "finalization outbox has no permanent proof",
                ))?;
            if durable.proof_id() != proof_id {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox id is not the permanent proof id",
                ));
            }
            let committed = durable.proof().finalized_block().header();
            if committed.height() != finalized.height()
                || committed.view() != finalized.view()
                || committed.id() != finalized.block_id()
                || committed.timestamp_ms() != finalized.timestamp_ms()
            {
                return Err(CoreError::InvalidRecovery(
                    "finalization outbox does not match finalized tip",
                ));
            }
        }
        if let Some(halt) = self.safety.safety_halt() {
            match halt {
                SafetyHalt::ConflictingQuorumCertificates { first, second } => {
                    if verify_durable_crypto {
                        self.verify_ordinary_qc(first, verifier)?;
                        self.verify_ordinary_qc(second, verifier)?;
                    }
                    let canonical = SafetyHalt::from_conflicting_qcs(
                        first.as_ref().clone(),
                        second.as_ref().clone(),
                    )?;
                    if &canonical != halt {
                        return Err(CoreError::InvalidRecovery(
                            "safety-halt QC pair is not canonically encoded",
                        ));
                    }
                }
                SafetyHalt::ConflictingPayloadValidation { first, second, .. } => {
                    // The two local terminal execution results are not network
                    // certificates. The durable halt itself is the fail-closed
                    // record and can never authorize recovery signing.
                    if (*first, *second)
                        != (
                            crate::PayloadTerminalResult::Valid,
                            crate::PayloadTerminalResult::DeterministicallyInvalid,
                        )
                    {
                        return Err(CoreError::InvalidRecovery(
                            "payload terminal conflict is not canonically encoded",
                        ));
                    }
                    let block_id = halt.payload_block_id().ok_or(CoreError::InvalidRecovery(
                        "payload-validation halt has no block identifier",
                    ))?;
                    if self.safety.payload_terminal_result(block_id).is_none() {
                        return Err(CoreError::InvalidRecovery(
                            "payload terminal conflict has no durable first fact",
                        ));
                    }
                }
                SafetyHalt::DeterministicallyInvalidPayload {
                    block_id,
                    reference,
                } => {
                    if self.safety.payload_terminal_result(*block_id)
                        != Some(PayloadTerminalResult::DeterministicallyInvalid)
                    {
                        return Err(CoreError::InvalidRecovery(
                            "invalid-payload halt has no durable invalid fact",
                        ));
                    }
                    match reference {
                        InvalidPayloadReference::QuorumCertificate(certificate) => {
                            if certificate.block_id() != *block_id {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload QC witness names a different block",
                                ));
                            }
                            if verify_durable_crypto {
                                self.verify_ordinary_qc(certificate, verifier)?;
                            }
                        }
                        InvalidPayloadReference::TimeoutCertificate(certificate) => {
                            let names_block = certificate
                                .referenced_qcs()
                                .iter()
                                .filter_map(QcReferenceV0::as_ordinary)
                                .any(|referenced| referenced.block_id() == *block_id);
                            if !names_block {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload TC witness does not reference the block",
                                ));
                            }
                            if self.safety.current_view()
                                < certificate.timed_out_view().checked_next()?
                            {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload TC witness is ahead of the durable view",
                                ));
                            }
                            if verify_durable_crypto {
                                certificate.verify(set, None, verifier)?;
                            }
                        }
                        InvalidPayloadReference::PendingVote(intent) => {
                            let SignIntent::Vote {
                                view,
                                height,
                                block_id: intent_block_id,
                                signing_root,
                            } = intent.as_ref()
                            else {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload halt cites a timeout-vote intent",
                                ));
                            };
                            if intent_block_id != block_id
                                || Vote::signing_root_for_set(
                                    set,
                                    *view,
                                    *height,
                                    *intent_block_id,
                                )? != *signing_root
                            {
                                return Err(CoreError::InvalidRecovery(
                                    "invalid-payload vote witness is malformed",
                                ));
                            }
                        }
                    }
                    let canonical = SafetyHalt::deterministically_invalid_payload(
                        *block_id,
                        reference.clone(),
                    )?;
                    if &canonical != halt {
                        return Err(CoreError::InvalidRecovery(
                            "invalid-payload halt is not canonically encoded",
                        ));
                    }
                }
            }
            if self.safety.pending_sign().is_some()
                || self.safety.pending_finalize().is_some()
                || self.safety.pending_tc_high_qc_sync().is_some()
                || self.safety.pending_standalone_qc_sync().is_some()
                || !self.safety.payload_validation_obligations().is_empty()
            {
                return Err(CoreError::InvalidRecovery(
                    "safety-halted state contains an active outbox or validation obligation",
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
        let high = self.safety.high_qc().qc_ref();
        let previous_high = previous.high_qc().qc_ref();
        if high.view() == previous_high.view() && high.block_id() != previous_high.block_id() {
            return Err(CoreError::InvalidRecovery(
                "high QC changed block at the same view",
            ));
        }
        if high.block_id() == previous_high.block_id()
            && (high.view() != previous_high.view() || high.height() != previous_high.height())
        {
            return Err(CoreError::InvalidRecovery(
                "high QC changed coordinates for one block",
            ));
        }
        if qc_order_key_ref(self.safety.high_qc()) < qc_order_key_ref(previous.high_qc()) {
            return Err(CoreError::InvalidRecovery("high QC regressed"));
        }

        let locked = self.safety.locked_qc().qc_ref();
        let previous_locked = previous.locked_qc().qc_ref();
        if locked.view() == previous_locked.view()
            && locked.block_id() != previous_locked.block_id()
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC changed block at the same view",
            ));
        }
        if locked.block_id() == previous_locked.block_id()
            && (locked.view() != previous_locked.view()
                || locked.height() != previous_locked.height())
        {
            return Err(CoreError::InvalidRecovery(
                "locked QC changed coordinates for one block",
            ));
        }
        if qc_order_key_ref(self.safety.locked_qc()) < qc_order_key_ref(previous.locked_qc()) {
            return Err(CoreError::InvalidRecovery("locked QC regressed"));
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
        match (
            previous.pending_tc_high_qc_sync(),
            self.safety.pending_tc_high_qc_sync(),
        ) {
            (Some(previous), Some(current)) if previous != current => {
                return Err(CoreError::InvalidRecovery(
                    "pending TC high-QC sync target changed",
                ));
            }
            (Some(previous), None) if self.safety.safety_halt().is_none() => {
                let selected_is_subsumed = match previous.selected_high_qc().as_ordinary() {
                    Some(certificate) => self.qc_is_durably_subsumed(certificate)?,
                    None => false,
                };
                if (!selected_is_subsumed
                    && qc_order_key_ref(self.safety.high_qc())
                        < qc_order_key_ref(previous.selected_high_qc()))
                    || self.safety.current_view() < previous.timed_out_view().checked_next()?
                {
                    return Err(CoreError::InvalidRecovery(
                        "pending TC sync cleared before adopting or subsuming its target",
                    ));
                }
            }
            _ => {}
        }
        let previous_standalone = previous.pending_standalone_qc_sync();
        let current_standalone = self.safety.pending_standalone_qc_sync();
        if previous_standalone != current_standalone
            && self.safety.revision() != previous.revision().saturating_add(1)
        {
            return Err(CoreError::InvalidRecovery(
                "standalone QC sync changed without a durable transition",
            ));
        }
        match (previous_standalone, current_standalone) {
            (None, Some(current)) if !current.backlog().is_empty() => {
                return Err(CoreError::InvalidRecovery(
                    "standalone QC sync was created with a backlog",
                ));
            }
            (Some(previous), current) if self.safety.safety_halt().is_none() => {
                let previous_queue: Vec<_> = core::iter::once(previous.active())
                    .chain(previous.backlog())
                    .collect();
                let current_queue: Vec<_> = current
                    .into_iter()
                    .flat_map(|pending| core::iter::once(pending.active()).chain(pending.backlog()))
                    .collect();
                let added: Vec<_> = current_queue
                    .iter()
                    .copied()
                    .filter(|certificate| !previous_queue.contains(certificate))
                    .collect();
                let removed: Vec<_> = previous_queue
                    .iter()
                    .copied()
                    .filter(|certificate| !current_queue.contains(certificate))
                    .collect();
                if !added.is_empty() {
                    if !removed.is_empty()
                        || added.len() > 1
                        || current.is_none_or(|pending| pending.active() != previous.active())
                        || !qc_sequence_is_subsequence(&previous_queue, &current_queue)
                    {
                        return Err(CoreError::InvalidRecovery(
                            "standalone QC backlog insertion replaced an existing target",
                        ));
                    }
                } else if !removed.is_empty() {
                    if !qc_sequence_is_subsequence(&current_queue, &previous_queue) {
                        return Err(CoreError::InvalidRecovery(
                            "standalone QC targets changed order while being cleared",
                        ));
                    }
                    let first_retained_index = previous_queue
                        .iter()
                        .position(|certificate| current_queue.contains(certificate))
                        .unwrap_or(previous_queue.len());
                    for (index, certificate) in previous_queue.iter().copied().enumerate() {
                        if !removed.contains(&certificate) {
                            continue;
                        }
                        let subsumed = self.qc_is_durably_subsumed(certificate)?;
                        let processed_ready_prefix = index < first_retained_index
                            && self.qc_is_ready_for_adoption(certificate)?
                            && qc_order_key_ref(self.safety.high_qc()) >= qc_order_key(certificate);
                        if !subsumed && !processed_ready_prefix {
                            return Err(CoreError::InvalidRecovery(
                                "standalone QC target was removed before processing or finality subsumption",
                            ));
                        }
                    }
                } else if previous_queue != current_queue {
                    return Err(CoreError::InvalidRecovery(
                        "standalone QC targets were replaced or reordered",
                    ));
                }
            }
            (None, None) | (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {}
        }
        if previous.safety_halt().is_some() && self.safety.safety_halt() != previous.safety_halt() {
            return Err(CoreError::InvalidRecovery(
                "safety halt was cleared or changed",
            ));
        }
        let previous_obligations = previous.payload_validation_obligations();
        let current_obligations = self.safety.payload_validation_obligations();
        for previous_obligation in previous_obligations {
            if let Ok(index) = current_obligations.binary_search_by_key(
                &previous_obligation.id(),
                DurablePayloadValidationObligationV0::id,
            ) {
                if &current_obligations[index] != previous_obligation {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation obligation changed in place",
                    ));
                }
            }
        }
        let added_obligations: Vec<_> = current_obligations
            .iter()
            .filter(|obligation| {
                previous_obligations
                    .binary_search_by_key(
                        &obligation.id(),
                        DurablePayloadValidationObligationV0::id,
                    )
                    .is_err()
            })
            .collect();
        let removed_obligations: Vec<_> = previous_obligations
            .iter()
            .filter(|obligation| {
                current_obligations
                    .binary_search_by_key(
                        &obligation.id(),
                        DurablePayloadValidationObligationV0::id,
                    )
                    .is_err()
            })
            .collect();
        if !added_obligations.is_empty() || !removed_obligations.is_empty() {
            if self.safety.revision() != previous.revision().saturating_add(1) {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations changed without one durable transition",
                ));
            }
            if added_obligations.len() > 1
                || added_obligations.iter().any(|obligation| {
                    obligation.first_recorded_revision() != self.safety.revision()
                })
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations were not inserted canonically",
                ));
            }
            if self.safety.safety_halt().is_none()
                && (!added_obligations.is_empty() && !removed_obligations.is_empty()
                    || removed_obligations.len() > 1)
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation obligations were replaced or removed in bulk",
                ));
            }
        }
        let previous_completions = previous.payload_validation_completions();
        let current_completions = self.safety.payload_validation_completions();
        for previous_completion in previous_completions {
            if let Ok(index) = current_completions.binary_search_by_key(
                &previous_completion.key(),
                DurablePayloadValidationCompletionV0::key,
            ) {
                if &current_completions[index] != previous_completion {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload validation completion changed in place",
                    ));
                }
            }
        }
        let added_completions: Vec<_> = current_completions
            .iter()
            .filter(|completion| {
                previous_completions
                    .binary_search_by_key(
                        &completion.key(),
                        DurablePayloadValidationCompletionV0::key,
                    )
                    .is_err()
            })
            .collect();
        let removed_completions: Vec<_> = previous_completions
            .iter()
            .filter(|completion| {
                current_completions
                    .binary_search_by_key(
                        &completion.key(),
                        DurablePayloadValidationCompletionV0::key,
                    )
                    .is_err()
            })
            .collect();
        if !removed_completions.is_empty() {
            return Err(CoreError::InvalidRecovery(
                "durable payload validation completion was removed without an acknowledged outbox retirement",
            ));
        }
        if !added_completions.is_empty() {
            if self.safety.revision() != previous.revision().saturating_add(1)
                || added_completions.len() != 1
                || added_completions[0].first_recorded_revision() != self.safety.revision()
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation completion was not inserted canonically in one durable transition",
                ));
            }
            let completion = added_completions[0];
            if !added_obligations.is_empty()
                || !removed_obligations.iter().any(|obligation| {
                    obligation.route() == completion.route() && obligation.id() == completion.id()
                })
            {
                return Err(CoreError::InvalidRecovery(
                    "payload validation completion did not consume its exact durable obligation",
                ));
            }
        } else if self.safety.safety_halt().is_none()
            && !removed_obligations.is_empty()
            && (!added_obligations.is_empty()
                || removed_obligations.len() != 1
                || removed_obligations[0].route() != PayloadValidationRouteV0::Synced)
        {
            return Err(CoreError::InvalidRecovery(
                    "payload validation obligation was removed without a completion or exact synced cancellation",
                ));
        }
        for previous_fact in previous.payload_terminal_facts() {
            if let Some(current) = self
                .safety
                .payload_terminal_facts()
                .iter()
                .find(|current| current.block_id() == previous_fact.block_id())
            {
                if current != previous_fact {
                    return Err(CoreError::InvalidRecovery(
                        "durable payload terminal fact changed",
                    ));
                }
            }
        }
        let removed: Vec<_> = previous
            .payload_terminal_facts()
            .iter()
            .filter(|previous_fact| {
                self.safety
                    .payload_terminal_result(previous_fact.block_id())
                    .is_none()
            })
            .collect();
        let added: Vec<_> = self
            .safety
            .payload_terminal_facts()
            .iter()
            .filter(|current_fact| {
                previous
                    .payload_terminal_result(current_fact.block_id())
                    .is_none()
            })
            .collect();
        if added.len() > 1
            || added
                .iter()
                .any(|fact| fact.first_recorded_revision() != self.safety.revision())
        {
            return Err(CoreError::InvalidRecovery(
                "payload terminal facts were not inserted by one durable transition",
            ));
        }
        if removed.is_empty() {
            if !added.is_empty()
                && previous.payload_terminal_facts().len() >= self.config.max_observed_messages()
            {
                return Err(CoreError::InvalidRecovery(
                    "full payload terminal cache grew without canonical eviction",
                ));
            }
        } else {
            if removed.len() != 1
                || added.len() != 1
                || previous.payload_terminal_facts().len() != self.config.max_observed_messages()
                || self.safety.payload_terminal_facts().len() != self.config.max_observed_messages()
            {
                return Err(CoreError::InvalidRecovery(
                    "payload terminal fact deletion is not a bounded replacement",
                ));
            }
            let protected = durable_payload_fact_blocks(previous);
            let expected = previous
                .payload_terminal_facts()
                .iter()
                .filter(|fact| !protected.contains(&fact.block_id()))
                .min_by_key(|fact| (fact.first_recorded_revision(), fact.block_id()))
                .map(|fact| fact.block_id())
                .ok_or(CoreError::InvalidRecovery(
                    "payload terminal replacement evicted a protected fact",
                ))?;
            if removed[0].block_id() != expected {
                return Err(CoreError::InvalidRecovery(
                    "payload terminal replacement did not evict the canonical oldest fact",
                ));
            }
        }
        Ok(())
    }
}

/// Checks only the parent/target context relation already implied by an exact
/// authenticated ancestry edge. Epoch-anchor authorization remains a separate
/// proposal-admission prerequisite; this helper must not make an epoch handoff
/// impossible by requiring its new context to equal the terminal old context.
pub(crate) fn payload_parent_context_matches_target_v0(
    target: &BlockHeader,
    parent: &BlockHeader,
) -> Result<bool> {
    if target.genesis_hash() != parent.genesis_hash() || target.chain_id() != parent.chain_id() {
        return Ok(false);
    }
    if target.block_kind() == BlockKind::EpochHandoff {
        return Ok(parent.block_kind() == BlockKind::EpochSeal2
            && target.epoch() == parent.epoch().checked_next()?);
    }
    Ok(target.protocol_version() == parent.protocol_version()
        && target.epoch() == parent.epoch()
        && target.validator_set_id() == parent.validator_set_id()
        && target.consensus_parameters_hash() == parent.consensus_parameters_hash())
}

/// Selects leaders by round-robin over the validator set's canonical order.
pub fn leader_for(validator_set: &ValidatorSet, view: View) -> ValidatorId {
    let validators = validator_set.validators();
    debug_assert!(!validators.is_empty());
    let index = (view.get().saturating_sub(1) % validators.len() as u64) as usize;
    validators[index].id()
}

fn proposal_referenced_qcs(proposal: &SignedProposalV0) -> Vec<&QuorumCertificate> {
    let mut certificates = Vec::new();
    if let Some(certificate) = proposal.witness().justify_qc().as_ordinary() {
        certificates.push(certificate);
    }
    if let Some(timeout) = proposal.witness().timeout_certificate() {
        for reference in timeout.referenced_qcs() {
            if let Some(certificate) = reference.as_ordinary() {
                if !certificates
                    .iter()
                    .any(|existing| existing.id() == certificate.id())
                {
                    certificates.push(certificate);
                }
            }
        }
    }
    certificates
}

fn ordinary_qcs_in_processing_order(certificate: &TimeoutCertificateV0) -> Vec<QuorumCertificate> {
    let mut certificates: Vec<_> = certificate
        .referenced_qcs()
        .iter()
        .filter_map(QcReferenceV0::as_ordinary)
        .cloned()
        .collect();
    certificates.sort_by_key(qc_order_key);
    certificates
}

fn pending_tc_sync_max_height(pending: &PendingTcHighQcSync) -> u64 {
    pending
        .timeout_certificate()
        .referenced_qcs()
        .iter()
        .map(|reference| reference.qc_ref().height().get())
        .max()
        .unwrap_or_else(|| pending.selected_high_qc().qc_ref().height().get())
}

fn pending_tc_contains_qc(pending: &PendingTcHighQcSync, certificate: &QuorumCertificate) -> bool {
    pending
        .timeout_certificate()
        .referenced_qcs()
        .iter()
        .filter_map(QcReferenceV0::as_ordinary)
        .any(|referenced| same_qc_coordinates(referenced, certificate))
}

fn pending_standalone_sync_max_height(pending: &PendingStandaloneQcSync) -> u64 {
    core::iter::once(pending.active())
        .chain(pending.backlog())
        .map(|certificate| certificate.height().get())
        .max()
        .unwrap_or_else(|| pending.active().height().get())
}

fn same_qc_coordinates(first: &QuorumCertificate, second: &QuorumCertificate) -> bool {
    first.view() == second.view()
        && first.height() == second.height()
        && first.block_id() == second.block_id()
}

fn qc_sequence_is_subsequence(
    candidate: &[&QuorumCertificate],
    sequence: &[&QuorumCertificate],
) -> bool {
    let mut matched = 0usize;
    for certificate in sequence {
        if candidate.get(matched) == Some(certificate) {
            matched = matched.saturating_add(1);
        }
    }
    matched == candidate.len()
}

fn durable_payload_fact_blocks(state: &SafetyState) -> Vec<BlockId> {
    let mut protected = vec![
        state.high_qc().qc_ref().block_id(),
        state.locked_qc().qc_ref().block_id(),
        state.finalized().block_id(),
    ];
    if let Some(pending) = state.pending_tc_high_qc_sync() {
        protected.extend(
            pending
                .timeout_certificate()
                .referenced_qcs()
                .iter()
                .map(|reference| reference.qc_ref().block_id()),
        );
    }
    if let Some(pending) = state.pending_standalone_qc_sync() {
        protected.extend(
            core::iter::once(pending.active())
                .chain(pending.backlog())
                .map(QuorumCertificate::block_id),
        );
    }
    if let Some(proof) = state.last_finalization_proof() {
        for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
            protected.push(certified.header().id());
            protected.push(certified.justify_qc().qc_ref().block_id());
            if let Some(timeout) = certified.timeout_certificate() {
                protected.extend(
                    timeout
                        .referenced_qcs()
                        .iter()
                        .map(|reference| reference.qc_ref().block_id()),
                );
            }
        }
    }
    if let Some(SignIntent::Vote { block_id, .. }) = state.pending_sign() {
        protected.push(*block_id);
    }
    if let Some(block_id) = state.safety_halt().and_then(SafetyHalt::payload_block_id) {
        protected.push(block_id);
    }
    protected.sort_unstable();
    protected.dedup();
    protected
}

fn safety_replay_required(state: &SafetyState) -> bool {
    state.high_qc().qc_ref().block_id() != state.finalized().block_id()
        || state.locked_qc().qc_ref().block_id() != state.finalized().block_id()
}

fn qc_order_key(certificate: &QuorumCertificate) -> (View, BlockId, CertificateId) {
    (certificate.view(), certificate.block_id(), certificate.id())
}

fn qc_order_key_ref(reference: &QcReferenceV0) -> (View, BlockId, CertificateId) {
    let summary = reference.qc_ref();
    (summary.view(), summary.block_id(), summary.qc_digest())
}

fn pending_validation_id(
    pending: &BTreeMap<ValidationId, SignedProposalV0>,
    proposal: &SignedProposalV0,
) -> Option<ValidationId> {
    pending
        .iter()
        .find(|(id, _)| {
            id.block_id() == proposal.block().id() && id.view() == proposal.block().header().view()
        })
        .map(|(id, _)| *id)
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
