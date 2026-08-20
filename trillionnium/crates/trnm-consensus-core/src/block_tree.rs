use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use trnm_consensus_types::{
    BlockHeader, BlockId, CertifiedHeaderV0, ConsensusParametersV0, FinalityProofV0,
    ProposalWitnessV0, QcRef, QcReferenceV0, QuorumCertificate, SignedProposalV0, ValidatorSet,
};

use crate::{
    BlockIdOverlayRefV0, CoreError, DurableFinalizationV0, FinalizedTip, PayloadValidationResult,
    Result,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockNode {
    header: BlockHeader,
    witness: ProposalWitnessV0,
    // The complete body is frozen only after this exact proposal crosses the
    // existing application-Valid boundary. Unknown/Unavailable bodies remain
    // source-scoped and replaceable exactly as they were before this field
    // existed.
    validated_proposal: Option<Arc<SignedProposalV0>>,
    validated_proposal_resource_bytes: usize,
    payload_status: PayloadStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadStatus {
    Unknown,
    Valid(BlockIdOverlayRefV0),
    DeterministicallyInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadTransition {
    Unavailable,
    RepeatedTerminal,
    BecameValid,
    BecameDeterministicallyInvalid,
    ConflictingValidOverlay,
    ConflictingTerminalResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ancestry {
    Descends,
    Conflicts,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockTree {
    max_blocks: usize,
    max_retained_validated_proposal_bytes: usize,
    retained_validated_proposal_bytes: usize,
    nodes: BTreeMap<BlockId, BlockNode>,
}

impl BlockTree {
    pub(crate) fn new(max_blocks: usize, max_retained_validated_proposal_bytes: usize) -> Self {
        Self {
            max_blocks,
            max_retained_validated_proposal_bytes,
            retained_validated_proposal_bytes: 0,
            nodes: BTreeMap::new(),
        }
    }

    /// Inserts the one exact, already-verified proposal envelope for a block.
    ///
    /// Header and witness identity become fixed immediately. The complete body
    /// is deliberately not frozen until application validation succeeds, so a
    /// source-scoped `Unavailable` result may still retry the authenticated
    /// header from another body source. Once frozen, only the exact complete
    /// proposal is idempotent; a different body can never replace it.
    pub(crate) fn insert_verified_proposal(
        &mut self,
        proposal: &SignedProposalV0,
        protected: &[BlockId],
    ) -> Result<()> {
        let header = proposal.block().header();
        let witness = proposal.witness();
        let block_id = header.id();
        if let Some(existing) = self.nodes.get(&block_id) {
            if &existing.header != header {
                return Err(CoreError::ConflictingBlock(block_id));
            }
            if &existing.witness != witness {
                return Err(CoreError::ConflictingProposalWitness(block_id));
            }
            if existing
                .validated_proposal
                .as_deref()
                .is_some_and(|validated| validated != proposal)
            {
                return Err(CoreError::ConflictingBlock(block_id));
            }
            return Ok(());
        }
        self.make_room(protected, header.parent_id())?;
        self.nodes.insert(
            block_id,
            BlockNode {
                header: header.clone(),
                witness: witness.clone(),
                validated_proposal: None,
                validated_proposal_resource_bytes: 0,
                payload_status: PayloadStatus::Unknown,
            },
        );
        Ok(())
    }

    pub(crate) fn validate_certificate_binding(
        &self,
        certificate: &QuorumCertificate,
    ) -> Result<()> {
        let Some(node) = self.nodes.get(&certificate.block_id()) else {
            return Err(CoreError::MissingBlock(certificate.block_id()));
        };
        if certificate.view() != node.header.view()
            || certificate.height() != node.header.height()
            || certificate.epoch() != node.header.epoch()
            || certificate.validator_set_id() != node.header.validator_set_id()
        {
            return Err(CoreError::ConflictingCertificate);
        }
        Ok(())
    }

    pub(crate) fn extends(&self, descendant: BlockId, ancestor: BlockId) -> bool {
        if descendant == ancestor {
            return true;
        }
        let mut cursor = descendant;
        for _ in 0..=self.max_blocks {
            let Some(node) = self.nodes.get(&cursor) else {
                return false;
            };
            let parent = node.header.parent_id();
            if parent == ancestor {
                return true;
            }
            if parent == cursor {
                return false;
            }
            cursor = parent;
        }
        false
    }

    pub(crate) fn contains_header(&self, block_id: BlockId) -> bool {
        self.nodes.contains_key(&block_id)
    }

    pub(crate) fn has_different_fixed_witness(
        &self,
        header: &BlockHeader,
        witness: &ProposalWitnessV0,
    ) -> Result<bool> {
        let Some(existing) = self.nodes.get(&header.id()) else {
            return Ok(false);
        };
        if &existing.header != header {
            return Err(CoreError::ConflictingBlock(header.id()));
        }
        Ok(&existing.witness != witness)
    }

    pub(crate) fn header(&self, block_id: BlockId) -> Option<&BlockHeader> {
        self.nodes.get(&block_id).map(|node| &node.header)
    }

    pub(crate) fn witness(&self, block_id: BlockId) -> Option<&ProposalWitnessV0> {
        self.nodes.get(&block_id).map(|node| &node.witness)
    }

    /// Returns the complete proposal frozen by an existing application-Valid
    /// transition. This is retained comparison data only: it is not an
    /// application-validity, finality, persistence, or signing authority.
    pub(crate) fn validated_proposal(&self, block_id: BlockId) -> Option<&SignedProposalV0> {
        self.nodes
            .get(&block_id)
            .and_then(|node| node.validated_proposal.as_deref())
    }

    #[cfg(test)]
    pub(crate) const fn retained_validated_proposal_bytes(&self) -> usize {
        self.retained_validated_proposal_bytes
    }

    #[cfg(test)]
    pub(crate) fn validated_proposal_arc_for_test(
        &self,
        block_id: BlockId,
    ) -> Option<&Arc<SignedProposalV0>> {
        self.nodes
            .get(&block_id)
            .and_then(|node| node.validated_proposal.as_ref())
    }

    #[cfg(test)]
    pub(crate) fn set_retention_budget_for_test(&mut self, maximum: usize) {
        self.max_retained_validated_proposal_bytes = maximum;
    }

    #[cfg(test)]
    pub(crate) fn retention_accounting_is_exact_for_test(&self) -> bool {
        self.nodes.values().try_fold(0_usize, |total, node| {
            total.checked_add(node.validated_proposal_resource_bytes)
        }) == Some(self.retained_validated_proposal_bytes)
    }

    /// Reconstructs the exact frozen proposal path from the finalized child
    /// through `target`, inclusive, in parent-to-child order.
    ///
    /// Every returned body previously crossed the existing application-Valid
    /// boundary, but this read-only projection mints no application, finality,
    /// persistence, recovery, or signing authority. Missing/unfrozen nodes,
    /// malformed edges, cycles, and paths beyond `maximum` all return `None`.
    #[allow(
        dead_code,
        reason = "the immediately following Core safety-shadow commit consumes this bounded prerequisite"
    )]
    pub(crate) fn exact_validated_proposal_path(
        &self,
        target: BlockId,
        finalized: FinalizedTip,
        maximum: usize,
        max_block_time_step_ms: u64,
    ) -> Option<Vec<&SignedProposalV0>> {
        let path = bounded_parent_path_v0(target, finalized.block_id(), maximum, |block_id| {
            let node = self.nodes.get(&block_id)?;
            let proposal = node.validated_proposal.as_ref()?;
            if proposal.block().header() != &node.header
                || proposal.witness() != &node.witness
                || proposal.block().id() != block_id
            {
                return None;
            }
            Some(proposal.block().header().parent_id())
        })?;

        let mut proposals = Vec::with_capacity(path.len());
        let mut previous_header = None;
        for block_id in path {
            let proposal = self.validated_proposal(block_id)?;
            let header = proposal.block().header();
            let justify = proposal.witness().justify_qc().qc_ref();
            let edge_matches = match previous_header {
                Some(parent) => {
                    edge_matches_header(header, justify, parent, max_block_time_step_ms)
                }
                None => edge_matches_finalized(header, justify, finalized, max_block_time_step_ms),
            };
            if !edge_matches || header.height() <= finalized.height() {
                return None;
            }
            previous_header = Some(header);
            proposals.push(proposal);
        }
        Some(proposals)
    }

    pub(crate) fn justify_qc(&self, block_id: BlockId) -> Option<&QcReferenceV0> {
        self.witness(block_id).map(ProposalWitnessV0::justify_qc)
    }

    fn record_payload_validation(
        &mut self,
        block_id: BlockId,
        result: PayloadValidationResult,
    ) -> Result<PayloadTransition> {
        let node = self
            .nodes
            .get_mut(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        // `Unavailable` is source-scoped and never becomes a negative fact
        // about the authenticated header. A new generation may retry the same
        // header with another body source or authenticated parent state.
        if result.is_unavailable() {
            return Ok(PayloadTransition::Unavailable);
        }
        let next = match result {
            PayloadValidationResult::Valid(valid) => {
                let overlay = valid.artifact_ref().overlay();
                if overlay.block_id() != block_id
                    || overlay.parent_block_id() != node.header.parent_id()
                {
                    return Err(CoreError::ConflictingPayloadValidation(block_id));
                }
                PayloadStatus::Valid(overlay)
            }
            PayloadValidationResult::DeterministicallyInvalid => {
                PayloadStatus::DeterministicallyInvalid
            }
            PayloadValidationResult::Unavailable => unreachable!(),
        };
        match (node.payload_status, next) {
            (PayloadStatus::Unknown, PayloadStatus::Valid(_)) => {
                node.payload_status = next;
                Ok(PayloadTransition::BecameValid)
            }
            (PayloadStatus::Unknown, PayloadStatus::DeterministicallyInvalid) => {
                node.payload_status = next;
                Ok(PayloadTransition::BecameDeterministicallyInvalid)
            }
            (PayloadStatus::Valid(first), PayloadStatus::Valid(second)) if first == second => {
                Ok(PayloadTransition::RepeatedTerminal)
            }
            (PayloadStatus::DeterministicallyInvalid, PayloadStatus::DeterministicallyInvalid) => {
                Ok(PayloadTransition::RepeatedTerminal)
            }
            (PayloadStatus::Valid(_), PayloadStatus::Valid(_)) => {
                Ok(PayloadTransition::ConflictingValidOverlay)
            }
            (PayloadStatus::Valid(_), PayloadStatus::DeterministicallyInvalid)
            | (PayloadStatus::DeterministicallyInvalid, PayloadStatus::Valid(_)) => {
                Ok(PayloadTransition::ConflictingTerminalResult)
            }
            (PayloadStatus::Unknown, PayloadStatus::Unknown)
            | (PayloadStatus::Valid(_), PayloadStatus::Unknown)
            | (PayloadStatus::DeterministicallyInvalid, PayloadStatus::Unknown) => unreachable!(),
        }
    }

    /// Restores only the durable deterministic-invalid fact. A caller cannot
    /// use this narrow API to mark a block Valid without supplying and freezing
    /// the exact complete proposal through the application-authenticated path.
    pub(crate) fn record_deterministically_invalid(
        &mut self,
        block_id: BlockId,
    ) -> Result<PayloadTransition> {
        self.record_payload_validation(block_id, PayloadValidationResult::DeterministicallyInvalid)
    }

    /// Applies one source-scoped validation result and freezes the complete
    /// proposal only when that exact body becomes application-Valid.
    pub(crate) fn record_payload_validation_for_proposal(
        &mut self,
        proposal: &SignedProposalV0,
        result: PayloadValidationResult,
    ) -> Result<PayloadTransition> {
        let block_id = proposal.block().id();
        let node = self
            .nodes
            .get(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        if proposal.block().header() != &node.header {
            return Err(CoreError::ConflictingBlock(block_id));
        }
        if proposal.witness() != &node.witness {
            return Err(CoreError::ConflictingProposalWitness(block_id));
        }
        if result.is_valid()
            && node
                .validated_proposal
                .as_deref()
                .is_some_and(|validated| validated != proposal)
        {
            return Err(CoreError::ConflictingBlock(block_id));
        }
        if result.artifact_ref().is_some_and(|artifact| {
            artifact.overlay().block_id() != block_id
                || artifact.overlay().parent_block_id() != node.header.parent_id()
        }) {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }

        let requested_resource_bytes = if result.is_valid()
            && node.validated_proposal.is_none()
            && match node.payload_status {
                PayloadStatus::Unknown => true,
                PayloadStatus::Valid(existing) => result
                    .artifact_ref()
                    .is_some_and(|artifact| artifact.overlay() == existing),
                PayloadStatus::DeterministicallyInvalid => false,
            } {
            Some(proposal.durable_validation_resource_size_v0()?)
        } else {
            None
        };
        let next_retained = requested_resource_bytes
            .map(|requested| self.checked_retained_total(requested))
            .transpose()?;

        let transition = self.record_payload_validation(block_id, result)?;
        if result.is_valid()
            && !matches!(
                transition,
                PayloadTransition::ConflictingValidOverlay
                    | PayloadTransition::ConflictingTerminalResult
            )
        {
            let node = self
                .nodes
                .get_mut(&block_id)
                .ok_or(CoreError::MissingBlock(block_id))?;
            match node.validated_proposal.as_deref() {
                Some(existing) if existing == proposal => {}
                Some(_) => return Err(CoreError::ConflictingBlock(block_id)),
                None => {
                    let requested =
                        requested_resource_bytes.ok_or(CoreError::ArithmeticOverflow(
                            "missing validated-proposal retention charge",
                        ))?;
                    node.validated_proposal = Some(Arc::new(proposal.clone()));
                    node.validated_proposal_resource_bytes = requested;
                    self.retained_validated_proposal_bytes = next_retained.ok_or(
                        CoreError::ArithmeticOverflow("missing validated-proposal retained total"),
                    )?;
                }
            }
        }
        Ok(transition)
    }

    /// Restores an application-authenticated durable Valid overlay after the
    /// dedicated anchored-successor recovery challenge has been accepted.
    ///
    /// This deliberately accepts no live validation commitments and is
    /// crate-private: generic recovery and peer input cannot call it. The
    /// exact header must already be installed and the overlay edge must match.
    /// The trusted reconciler, not this helper, proves that the inert durable
    /// commitments equal application execution of the exact body.
    pub(crate) fn restore_authenticated_valid_overlay_v0(
        &mut self,
        proposal: &SignedProposalV0,
        overlay: BlockIdOverlayRefV0,
    ) -> Result<()> {
        let block_id = proposal.block().id();
        let node = self
            .nodes
            .get(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        if proposal.block().header() != &node.header {
            return Err(CoreError::ConflictingBlock(block_id));
        }
        if proposal.witness() != &node.witness {
            return Err(CoreError::ConflictingProposalWitness(block_id));
        }
        if overlay.block_id() != block_id || overlay.parent_block_id() != node.header.parent_id() {
            return Err(CoreError::ConflictingPayloadValidation(block_id));
        }
        if node
            .validated_proposal
            .as_deref()
            .is_some_and(|validated| validated != proposal)
        {
            return Err(CoreError::ConflictingBlock(block_id));
        }
        let needs_install = node.validated_proposal.is_none()
            && match node.payload_status {
                PayloadStatus::Unknown => true,
                PayloadStatus::Valid(existing) => existing == overlay,
                PayloadStatus::DeterministicallyInvalid => false,
            };
        let requested_resource_bytes = needs_install
            .then(|| proposal.durable_validation_resource_size_v0())
            .transpose()?;
        let next_retained = requested_resource_bytes
            .map(|requested| self.checked_retained_total(requested))
            .transpose()?;
        let node = self
            .nodes
            .get_mut(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        match node.payload_status {
            PayloadStatus::Unknown => {
                node.payload_status = PayloadStatus::Valid(overlay);
                let requested = requested_resource_bytes.ok_or(CoreError::ArithmeticOverflow(
                    "missing restored-proposal retention charge",
                ))?;
                node.validated_proposal = Some(Arc::new(proposal.clone()));
                node.validated_proposal_resource_bytes = requested;
                self.retained_validated_proposal_bytes = next_retained.ok_or(
                    CoreError::ArithmeticOverflow("missing restored-proposal retained total"),
                )?;
                Ok(())
            }
            PayloadStatus::Valid(existing) if existing == overlay => {
                if node.validated_proposal.is_none() {
                    let requested = requested_resource_bytes.ok_or(
                        CoreError::ArithmeticOverflow("missing restored-proposal retention charge"),
                    )?;
                    node.validated_proposal = Some(Arc::new(proposal.clone()));
                    node.validated_proposal_resource_bytes = requested;
                    self.retained_validated_proposal_bytes = next_retained.ok_or(
                        CoreError::ArithmeticOverflow("missing restored-proposal retained total"),
                    )?;
                }
                Ok(())
            }
            PayloadStatus::Valid(_) | PayloadStatus::DeterministicallyInvalid => {
                Err(CoreError::ConflictingPayloadValidation(block_id))
            }
        }
    }

    pub(crate) fn payload_is_known(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| node.payload_status != PayloadStatus::Unknown)
    }

    pub(crate) fn payload_is_invalid(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| node.payload_status == PayloadStatus::DeterministicallyInvalid)
    }

    pub(crate) fn payload_is_valid(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| matches!(node.payload_status, PayloadStatus::Valid(_)))
    }

    pub(crate) fn payload_overlay_ref(&self, block_id: BlockId) -> Option<BlockIdOverlayRefV0> {
        match self.nodes.get(&block_id)?.payload_status {
            PayloadStatus::Valid(overlay) => Some(overlay),
            PayloadStatus::Unknown | PayloadStatus::DeterministicallyInvalid => None,
        }
    }

    pub(crate) fn validate_proposal_parent(
        &self,
        child: &BlockHeader,
        justify_qc: QcRef,
        finalized: FinalizedTip,
        max_block_time_step_ms: u64,
    ) -> Ancestry {
        let parent_id = child.parent_id();
        if parent_id == finalized.block_id() {
            return if edge_matches_finalized(child, justify_qc, finalized, max_block_time_step_ms) {
                Ancestry::Descends
            } else {
                Ancestry::Conflicts
            };
        }
        let Some(parent) = self.nodes.get(&parent_id) else {
            return Ancestry::Unknown;
        };
        if parent.payload_status == PayloadStatus::DeterministicallyInvalid {
            return Ancestry::Conflicts;
        }
        if parent.payload_status == PayloadStatus::Unknown {
            return Ancestry::Unknown;
        }
        if !edge_matches_header(child, justify_qc, &parent.header, max_block_time_step_ms) {
            return Ancestry::Conflicts;
        }
        self.validated_ancestry(parent_id, finalized, max_block_time_step_ms)
    }

    pub(crate) fn validated_ancestry(
        &self,
        descendant: BlockId,
        finalized: FinalizedTip,
        max_block_time_step_ms: u64,
    ) -> Ancestry {
        if descendant == finalized.block_id() {
            return Ancestry::Descends;
        }
        let mut cursor = descendant;
        for _ in 0..=self.max_blocks {
            let Some(node) = self.nodes.get(&cursor) else {
                return Ancestry::Unknown;
            };
            match node.payload_status {
                PayloadStatus::DeterministicallyInvalid => return Ancestry::Conflicts,
                PayloadStatus::Unknown => return Ancestry::Unknown,
                PayloadStatus::Valid(_) => {}
            }
            let height = node.header.height().get();
            if height <= finalized.height().get() {
                return Ancestry::Conflicts;
            }
            let parent = node.header.parent_id();
            let justify_qc = node.witness.justify_qc().qc_ref();
            if parent == finalized.block_id() {
                return if edge_matches_finalized(
                    &node.header,
                    justify_qc,
                    finalized,
                    max_block_time_step_ms,
                ) {
                    Ancestry::Descends
                } else {
                    Ancestry::Conflicts
                };
            }
            if parent == cursor {
                return Ancestry::Conflicts;
            }
            let Some(parent_node) = self.nodes.get(&parent) else {
                return Ancestry::Unknown;
            };
            if !edge_matches_header(
                &node.header,
                justify_qc,
                &parent_node.header,
                max_block_time_step_ms,
            ) {
                return Ancestry::Conflicts;
            }
            cursor = parent;
        }
        Ancestry::Unknown
    }

    pub(crate) fn detect_three_chain(
        &self,
        newest_certificate: &QuorumCertificate,
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
        finalized: FinalizedTip,
    ) -> Result<Option<DurableFinalizationV0>> {
        let Some(grandchild_node) = self.nodes.get(&newest_certificate.block_id()) else {
            return Ok(None);
        };
        let Some(child_node) = self.nodes.get(&grandchild_node.header.parent_id()) else {
            return Ok(None);
        };
        let Some(committed_node) = self.nodes.get(&child_node.header.parent_id()) else {
            return Ok(None);
        };
        // A repeated or later QC may reproduce a three-chain whose first
        // block was already finalized. Its authenticated direct parent may
        // have been pruned, so recognize the proof as an idempotent no-op
        // before attempting to reconstruct it.
        if committed_node.header.height() <= finalized.height() {
            return Ok(None);
        }
        if [committed_node, child_node, grandchild_node]
            .iter()
            .any(|node| !matches!(node.payload_status, PayloadStatus::Valid(_)))
        {
            return Ok(None);
        }
        let PayloadStatus::Valid(target_overlay_ref) = committed_node.payload_status else {
            return Ok(None);
        };
        let committed_qc = child_node
            .witness
            .justify_qc()
            .as_ordinary()
            .cloned()
            .ok_or(CoreError::InvalidOrdinaryCertificate)?;
        let child_qc = grandchild_node
            .witness
            .justify_qc()
            .as_ordinary()
            .cloned()
            .ok_or(CoreError::InvalidOrdinaryCertificate)?;
        let grandchild_qc = newest_certificate.clone();
        let authenticated_parent = self.authenticated_parent(&committed_node.header, finalized)?;
        let committed = CertifiedHeaderV0::from_proposal_witness(
            committed_node.header.clone(),
            committed_node.witness.clone(),
            committed_qc,
            validator_set,
            None,
            consensus_parameters,
            authenticated_parent.timestamp_ms(),
        )?;
        let child = CertifiedHeaderV0::from_proposal_witness(
            child_node.header.clone(),
            child_node.witness.clone(),
            child_qc,
            validator_set,
            None,
            consensus_parameters,
            committed_node.header.timestamp_ms(),
        )?;
        let grandchild = CertifiedHeaderV0::from_proposal_witness(
            grandchild_node.header.clone(),
            grandchild_node.witness.clone(),
            grandchild_qc,
            validator_set,
            None,
            consensus_parameters,
            child_node.header.timestamp_ms(),
        )?;
        let proof = FinalityProofV0::new(
            committed,
            child,
            grandchild,
            validator_set,
            None,
            consensus_parameters,
            authenticated_parent.timestamp_ms(),
        )?;
        Ok(Some(DurableFinalizationV0::new(
            authenticated_parent,
            proof,
            target_overlay_ref,
        )?))
    }

    /// Reconstructs every newly implied three-chain proof in ancestor order.
    ///
    /// A lagging node may first receive a QC several blocks above its durable
    /// finalized tip.  The newest QC still authenticates the intervening QCs:
    /// each verified proposal witness carries the exact QC for its parent.
    /// Returning only the newest three-chain would therefore skip application
    /// finalizations even though the complete certified prefix is already
    /// present and payload-Valid in this tree.
    ///
    /// This routine is read-only and builds the complete suffix before Core
    /// mutates SafetyState.  An incomplete or non-monotonic suffix fails
    /// closed; callers must never coalesce it into the newest proof.
    pub(crate) fn detect_three_chain_suffix(
        &self,
        newest_certificate: &QuorumCertificate,
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
        finalized: FinalizedTip,
    ) -> Result<Vec<DurableFinalizationV0>> {
        let mut newest = newest_certificate.clone();
        let mut newest_first = Vec::new();

        for _ in 0..=self.max_blocks {
            let Some(finalization) =
                self.detect_three_chain(&newest, validator_set, consensus_parameters, finalized)?
            else {
                break;
            };
            let authenticated_parent = finalization.authenticated_parent();
            newest_first.push(finalization);
            if authenticated_parent == finalized {
                newest_first.reverse();
                let mut expected_parent = finalized;
                for finalization in &newest_first {
                    if finalization.authenticated_parent() != expected_parent {
                        return Err(CoreError::ConflictingCertificate);
                    }
                    let committed = finalization.proof().finalized_block().header();
                    expected_parent = FinalizedTip::new(
                        committed.height(),
                        committed.view(),
                        committed.id(),
                        committed.timestamp_ms(),
                    );
                }
                return Ok(newest_first);
            }

            if authenticated_parent.height() <= finalized.height() {
                return Err(CoreError::ConflictingCertificate);
            }
            let newest_node = self
                .nodes
                .get(&newest.block_id())
                .ok_or(CoreError::MissingBlock(newest.block_id()))?;
            let previous = newest_node
                .witness
                .justify_qc()
                .as_ordinary()
                .cloned()
                .ok_or(CoreError::InvalidOrdinaryCertificate)?;
            if previous.block_id() != newest_node.header.parent_id()
                || previous.height().checked_next()? != newest.height()
            {
                return Err(CoreError::ConflictingCertificate);
            }
            newest = previous;
        }

        if newest_first.is_empty() {
            Ok(Vec::new())
        } else {
            Err(CoreError::MissingBlock(
                newest_first
                    .last()
                    .expect("a nonempty suffix has a finalization")
                    .authenticated_parent()
                    .block_id(),
            ))
        }
    }

    pub(crate) fn prune_below(
        &mut self,
        finalized_height: u64,
        finalized_id: BlockId,
        protected: &[BlockId],
    ) -> Result<()> {
        let removed: Vec<_> = self
            .nodes
            .iter()
            .filter_map(|(block_id, node)| {
                (*block_id != finalized_id
                    && node.header.height().get() < finalized_height
                    && !protected.contains(block_id))
                .then_some(*block_id)
            })
            .collect();
        let released = removed.iter().try_fold(0_usize, |total, block_id| {
            total
                .checked_add(
                    self.nodes
                        .get(block_id)
                        .ok_or(CoreError::MissingBlock(*block_id))?
                        .validated_proposal_resource_bytes,
                )
                .ok_or(CoreError::ArithmeticOverflow(
                    "pruned validated-proposal resource bytes",
                ))
        })?;
        let next_retained = self
            .retained_validated_proposal_bytes
            .checked_sub(released)
            .ok_or(CoreError::ArithmeticOverflow(
                "pruned validated-proposal resource release",
            ))?;
        for block_id in removed {
            self.nodes.remove(&block_id);
        }
        self.retained_validated_proposal_bytes = next_retained;
        Ok(())
    }

    fn make_room(&mut self, protected: &[BlockId], incoming_parent: BlockId) -> Result<()> {
        if self.nodes.len() < self.max_blocks {
            return Ok(());
        }
        let candidate = self
            .nodes
            .iter()
            .filter(|(block_id, _)| {
                !protected.contains(block_id)
                    && **block_id != incoming_parent
                    && !self.extends(incoming_parent, **block_id)
                    && !protected
                        .iter()
                        .any(|anchor| self.extends(*anchor, **block_id))
            })
            .min_by_key(|(block_id, node)| (node.header.height(), node.header.view(), **block_id))
            .map(|(block_id, _)| *block_id)
            .ok_or(CoreError::BlockTreeFull)?;
        self.remove_node(candidate)?;
        Ok(())
    }

    fn checked_retained_total(&self, requested: usize) -> Result<usize> {
        let next = self
            .retained_validated_proposal_bytes
            .checked_add(requested)
            .ok_or(CoreError::ArithmeticOverflow(
                "retained validated-proposal resource bytes",
            ))?;
        if next > self.max_retained_validated_proposal_bytes {
            return Err(CoreError::ValidatedProposalRetentionBudgetExceeded {
                retained: self.retained_validated_proposal_bytes,
                requested,
                maximum: self.max_retained_validated_proposal_bytes,
            });
        }
        Ok(next)
    }

    fn remove_node(&mut self, block_id: BlockId) -> Result<Option<BlockNode>> {
        let Some(resource_bytes) = self
            .nodes
            .get(&block_id)
            .map(|node| node.validated_proposal_resource_bytes)
        else {
            return Ok(None);
        };
        let next_retained = self
            .retained_validated_proposal_bytes
            .checked_sub(resource_bytes)
            .ok_or(CoreError::ArithmeticOverflow(
                "retained validated-proposal resource release",
            ))?;
        let node = self
            .nodes
            .remove(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        self.retained_validated_proposal_bytes = next_retained;
        Ok(Some(node))
    }

    fn authenticated_parent(
        &self,
        child: &BlockHeader,
        finalized: FinalizedTip,
    ) -> Result<FinalizedTip> {
        if child.parent_id() == finalized.block_id() {
            return Ok(finalized);
        }
        let parent = self
            .nodes
            .get(&child.parent_id())
            .ok_or(CoreError::MissingBlock(child.parent_id()))?;
        if !matches!(parent.payload_status, PayloadStatus::Valid(_)) {
            return Err(CoreError::MissingBlock(child.parent_id()));
        }
        Ok(FinalizedTip::new(
            parent.header.height(),
            parent.header.view(),
            parent.header.id(),
            parent.header.timestamp_ms(),
        ))
    }
}

fn bounded_parent_path_v0<F>(
    target: BlockId,
    finalized: BlockId,
    maximum: usize,
    mut parent_for: F,
) -> Option<Vec<BlockId>>
where
    F: FnMut(BlockId) -> Option<BlockId>,
{
    if maximum == 0 || target == finalized {
        return None;
    }
    let mut newest_first = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = target;
    for _ in 0..maximum {
        if !seen.insert(cursor) {
            return None;
        }
        newest_first.push(cursor);
        let parent = parent_for(cursor)?;
        if parent == finalized {
            newest_first.reverse();
            return Some(newest_first);
        }
        cursor = parent;
    }
    None
}

fn edge_matches_finalized(
    child: &BlockHeader,
    justify_qc: QcRef,
    finalized: FinalizedTip,
    max_block_time_step_ms: u64,
) -> bool {
    edge_coordinates_match(
        child,
        justify_qc,
        finalized.block_id(),
        finalized.height().get(),
        finalized.view().get(),
        finalized.timestamp_ms(),
        max_block_time_step_ms,
    )
}

fn edge_matches_header(
    child: &BlockHeader,
    justify_qc: QcRef,
    parent: &BlockHeader,
    max_block_time_step_ms: u64,
) -> bool {
    edge_coordinates_match(
        child,
        justify_qc,
        parent.id(),
        parent.height().get(),
        parent.view().get(),
        parent.timestamp_ms(),
        max_block_time_step_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn edge_coordinates_match(
    child: &BlockHeader,
    justify_qc: QcRef,
    parent_id: BlockId,
    parent_height: u64,
    parent_view: u64,
    parent_timestamp_ms: u64,
    max_block_time_step_ms: u64,
) -> bool {
    let Some(expected_height) = parent_height.checked_add(1) else {
        return false;
    };
    let Some(maximum_timestamp) = parent_timestamp_ms.checked_add(max_block_time_step_ms) else {
        return false;
    };
    child.parent_id() == parent_id
        && child.height().get() == expected_height
        && child.view().get() > parent_view
        && child.timestamp_ms() > parent_timestamp_ms
        && child.timestamp_ms() <= maximum_timestamp
        && justify_qc.block_id() == parent_id
        && justify_qc.height().get() == parent_height
        && justify_qc.view().get() == parent_view
}

#[cfg(test)]
mod retention_tests {
    use super::{bounded_parent_path_v0, BlockId, BlockTree, CoreError};

    #[test]
    fn retained_resource_addition_overflow_fails_before_mutation() {
        let mut tree = BlockTree::new(4, usize::MAX);
        tree.retained_validated_proposal_bytes = usize::MAX;
        let before = tree.clone();
        assert_eq!(
            tree.checked_retained_total(1),
            Err(CoreError::ArithmeticOverflow(
                "retained validated-proposal resource bytes"
            ))
        );
        assert_eq!(tree, before);
    }

    #[test]
    fn bounded_parent_path_rejects_a_cycle_before_reaching_finality() {
        let first = BlockId::new([1; 32]);
        let second = BlockId::new([2; 32]);
        let finalized = BlockId::new([3; 32]);
        assert!(bounded_parent_path_v0(first, finalized, 4, |block_id| {
            match block_id {
                value if value == first => Some(second),
                value if value == second => Some(first),
                _ => None,
            }
        })
        .is_none());
    }
}
