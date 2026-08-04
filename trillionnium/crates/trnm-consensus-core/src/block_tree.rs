use alloc::collections::BTreeMap;

use trnm_consensus_types::{BlockHeader, BlockId, CommitProof, QuorumCertificate, ValidatorSet};

use crate::{CoreError, FinalizedTip, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockNode {
    header: BlockHeader,
    justify_qc: Option<QuorumCertificate>,
    certificate: Option<QuorumCertificate>,
    payload_status: PayloadStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadStatus {
    Unknown,
    Valid,
    Invalid,
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

    pub(crate) fn insert_header(
        &mut self,
        header: BlockHeader,
        justify_qc: Option<QuorumCertificate>,
        protected: &[BlockId],
    ) -> Result<()> {
        let block_id = header.id();
        if let Some(existing) = self.nodes.get_mut(&block_id) {
            if existing.header != header {
                return Err(CoreError::ConflictingBlock(block_id));
            }
            match (&existing.justify_qc, justify_qc) {
                (Some(current), Some(candidate)) => {
                    if !same_qc_coordinate(current, &candidate) {
                        return Err(CoreError::ConflictingCertificate);
                    }
                    if candidate.id() > current.id() {
                        existing.justify_qc = Some(candidate);
                    }
                }
                (None, Some(candidate)) => existing.justify_qc = Some(candidate),
                (Some(_), None) | (None, None) => {}
            }
            return Ok(());
        }
        self.make_room(protected)?;
        self.nodes.insert(
            block_id,
            BlockNode {
                header,
                justify_qc,
                certificate: None,
                payload_status: PayloadStatus::Unknown,
            },
        );
        Ok(())
    }

    pub(crate) fn attach_certificate(&mut self, certificate: &QuorumCertificate) -> Result<()> {
        let Some(node) = self.nodes.get_mut(&certificate.block_id()) else {
            return Ok(());
        };
        if certificate.view() != node.header.view()
            || certificate.height() != node.header.height()
            || certificate.epoch() != node.header.epoch()
            || certificate.validator_set_id() != node.header.validator_set_id()
        {
            return Err(CoreError::ConflictingCertificate);
        }
        match &node.certificate {
            Some(existing)
                if existing.view() != certificate.view()
                    || existing.height() != certificate.height()
                    || existing.block_id() != certificate.block_id() =>
            {
                Err(CoreError::ConflictingCertificate)
            }
            Some(existing) => {
                if certificate.id() > existing.id() {
                    node.certificate = Some(certificate.clone());
                }
                Ok(())
            }
            None => {
                node.certificate = Some(certificate.clone());
                Ok(())
            }
        }
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

    pub(crate) fn justify_qc(&self, block_id: BlockId) -> Option<&QuorumCertificate> {
        self.nodes
            .get(&block_id)
            .and_then(|node| node.justify_qc.as_ref())
    }

    pub(crate) fn set_payload_validity(&mut self, block_id: BlockId, valid: bool) -> Result<()> {
        let node = self
            .nodes
            .get_mut(&block_id)
            .ok_or(CoreError::MissingBlock(block_id))?;
        let status = if valid {
            PayloadStatus::Valid
        } else {
            PayloadStatus::Invalid
        };
        match node.payload_status {
            PayloadStatus::Unknown => node.payload_status = status,
            existing if existing == status => {}
            PayloadStatus::Valid | PayloadStatus::Invalid => {
                return Err(CoreError::ConflictingPayloadValidation(block_id));
            }
        }
        Ok(())
    }

    pub(crate) fn payload_is_known(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| node.payload_status != PayloadStatus::Unknown)
    }

    pub(crate) fn payload_is_invalid(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| node.payload_status == PayloadStatus::Invalid)
    }

    pub(crate) fn payload_is_valid(&self, block_id: BlockId) -> bool {
        self.nodes
            .get(&block_id)
            .is_some_and(|node| node.payload_status == PayloadStatus::Valid)
    }

    pub(crate) fn validate_proposal_parent(
        &self,
        child: &BlockHeader,
        justify_qc: &QuorumCertificate,
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
        if parent.payload_status == PayloadStatus::Invalid {
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
                PayloadStatus::Invalid => return Ancestry::Conflicts,
                PayloadStatus::Unknown => return Ancestry::Unknown,
                PayloadStatus::Valid => {}
            }
            let height = node.header.height().get();
            if height <= finalized.height().get() {
                return Ancestry::Conflicts;
            }
            let parent = node.header.parent_id();
            let Some(justify_qc) = node.justify_qc.as_ref() else {
                return Ancestry::Conflicts;
            };
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
    ) -> Result<Option<CommitProof>> {
        let Some(grandchild_node) = self.nodes.get(&newest_certificate.block_id()) else {
            return Ok(None);
        };
        let Some(child_node) = self.nodes.get(&grandchild_node.header.parent_id()) else {
            return Ok(None);
        };
        let Some(committed_node) = self.nodes.get(&child_node.header.parent_id()) else {
            return Ok(None);
        };
        if [committed_node, child_node, grandchild_node]
            .iter()
            .any(|node| node.payload_status != PayloadStatus::Valid)
        {
            return Ok(None);
        }
        let Some(committed_qc) = child_node.justify_qc.clone() else {
            return Ok(None);
        };
        let Some(child_qc) = grandchild_node.justify_qc.clone() else {
            return Ok(None);
        };
        let grandchild_qc = newest_certificate.clone();
        Ok(Some(CommitProof::new(
            committed_node.header.clone(),
            child_node.header.clone(),
            grandchild_node.header.clone(),
            committed_qc,
            child_qc,
            grandchild_qc,
            validator_set,
        )?))
    }

    pub(crate) fn prune_below(&mut self, finalized_height: u64, finalized_id: BlockId) {
        self.nodes.retain(|block_id, node| {
            *block_id == finalized_id || node.header.height().get() >= finalized_height
        });
    }

    fn make_room(&mut self, protected: &[BlockId]) -> Result<()> {
        if self.nodes.len() < self.max_blocks {
            return Ok(());
        }
        let candidate = self
            .nodes
            .iter()
            .filter(|(block_id, _)| {
                !protected.contains(block_id)
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
}

fn same_qc_coordinate(first: &QuorumCertificate, second: &QuorumCertificate) -> bool {
    first.chain_id() == second.chain_id()
        && first.protocol_version() == second.protocol_version()
        && first.epoch() == second.epoch()
        && first.view() == second.view()
        && first.height() == second.height()
        && first.block_id() == second.block_id()
        && first.validator_set_id() == second.validator_set_id()
}

fn edge_matches_finalized(
    child: &BlockHeader,
    justify_qc: &QuorumCertificate,
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
    justify_qc: &QuorumCertificate,
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
    justify_qc: &QuorumCertificate,
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
