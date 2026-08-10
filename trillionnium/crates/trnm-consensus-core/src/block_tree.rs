use alloc::collections::BTreeMap;

use trnm_consensus_types::{
    BlockHeader, BlockId, CertifiedHeaderV0, ConsensusParametersV0, FinalityProofV0,
    ProposalWitnessV0, QcRef, QcReferenceV0, QuorumCertificate, ValidatorSet,
};

use crate::{CoreError, DurableFinalizationV0, FinalizedTip, PayloadValidationResult, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockNode {
    header: BlockHeader,
    witness: ProposalWitnessV0,
    payload_status: PayloadStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadStatus {
    Unknown,
    Valid,
    DeterministicallyInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadTransition {
    Unavailable,
    RepeatedTerminal,
    BecameValid,
    BecameDeterministicallyInvalid,
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
    nodes: BTreeMap<BlockId, BlockNode>,
}

impl BlockTree {
    pub(crate) fn new(max_blocks: usize) -> Self {
        Self {
            max_blocks,
            nodes: BTreeMap::new(),
        }
    }

    /// Inserts the one exact, already-verified proposal witness for a block.
    ///
    /// A repeated proposal is idempotent only when both its header and witness
    /// are byte-for-byte the same semantic values. In particular, a later QC
    /// or TC cannot replace the justification that the proposer actually
    /// signed and that a future finality proof must reproduce exactly.
    pub(crate) fn insert_verified_proposal(
        &mut self,
        header: BlockHeader,
        witness: ProposalWitnessV0,
        protected: &[BlockId],
    ) -> Result<()> {
        let block_id = header.id();
        if let Some(existing) = self.nodes.get(&block_id) {
            if existing.header != header {
                return Err(CoreError::ConflictingBlock(block_id));
            }
            if existing.witness != witness {
                return Err(CoreError::ConflictingProposalWitness(block_id));
            }
            return Ok(());
        }
        self.make_room(protected, header.parent_id())?;
        self.nodes.insert(
            block_id,
            BlockNode {
                header,
                witness,
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

    pub(crate) fn justify_qc(&self, block_id: BlockId) -> Option<&QcReferenceV0> {
        self.witness(block_id).map(ProposalWitnessV0::justify_qc)
    }

    pub(crate) fn record_payload_validation(
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
            PayloadValidationResult::Valid { .. } => PayloadStatus::Valid,
            PayloadValidationResult::DeterministicallyInvalid => {
                PayloadStatus::DeterministicallyInvalid
            }
            PayloadValidationResult::Unavailable => unreachable!(),
        };
        match (node.payload_status, next) {
            (PayloadStatus::Unknown, PayloadStatus::Valid) => {
                node.payload_status = next;
                Ok(PayloadTransition::BecameValid)
            }
            (PayloadStatus::Unknown, PayloadStatus::DeterministicallyInvalid) => {
                node.payload_status = next;
                Ok(PayloadTransition::BecameDeterministicallyInvalid)
            }
            (PayloadStatus::Valid, PayloadStatus::Valid)
            | (PayloadStatus::DeterministicallyInvalid, PayloadStatus::DeterministicallyInvalid) => {
                Ok(PayloadTransition::RepeatedTerminal)
            }
            (PayloadStatus::Valid, PayloadStatus::DeterministicallyInvalid)
            | (PayloadStatus::DeterministicallyInvalid, PayloadStatus::Valid) => {
                Ok(PayloadTransition::ConflictingTerminalResult)
            }
            (PayloadStatus::Unknown, PayloadStatus::Unknown)
            | (PayloadStatus::Valid, PayloadStatus::Unknown)
            | (PayloadStatus::DeterministicallyInvalid, PayloadStatus::Unknown) => unreachable!(),
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
            .is_some_and(|node| node.payload_status == PayloadStatus::Valid)
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
                PayloadStatus::Valid => {}
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
            .any(|node| node.payload_status != PayloadStatus::Valid)
        {
            return Ok(None);
        }
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
        )?))
    }

    pub(crate) fn prune_below(
        &mut self,
        finalized_height: u64,
        finalized_id: BlockId,
        protected: &[BlockId],
    ) {
        self.nodes.retain(|block_id, node| {
            *block_id == finalized_id
                || node.header.height().get() >= finalized_height
                || protected.contains(block_id)
        });
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
        self.nodes.remove(&candidate);
        Ok(())
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
        if parent.payload_status != PayloadStatus::Valid {
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
