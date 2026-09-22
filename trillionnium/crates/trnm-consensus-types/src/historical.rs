//! Inert structural checks shared by historical header consumers.

use crate::proposal_v0::{
    validate_header_set_binding, validate_parameters_binding, validate_scheduled_leader,
    validate_timestamp_step,
};
use crate::{
    BlockHeader, BlockKind, ConsensusParametersV0, EpochGeometryV0, OrderedRootV0, Result,
    RootKind, ValidatorSet,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Local history admission limits. The strict M01 consumer clamps these to its
/// hard ceilings; these fields cannot widen a frozen CEV0 object budget.
pub struct HistoricalAncestryLimitsV1 {
    pub maximum_headers: usize,
    pub maximum_transitions: usize,
    pub maximum_total_bytes: usize,
}

impl Default for HistoricalAncestryLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_headers: 256,
            maximum_transitions: 32,
            maximum_total_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Check one exact ancestor link in the active context of `header`. This is
/// structural validation only, with no QC, TC or signature authority. At a
/// handoff the caller must separately verify the old geometry/activation; the
/// supplied set/parameters are the authenticated new context, not the parent's.
pub fn validate_historical_header_link_v1(
    header: &BlockHeader,
    parent: &BlockHeader,
    active_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<()> {
    header.validate_shape()?;
    parent.validate_shape()?;
    active_set.validate_against_parameters(parameters)?;
    validate_header_set_binding(header, active_set)?;
    validate_parameters_binding(header, active_set, parameters)?;
    validate_scheduled_leader(header, active_set, parameters)?;
    let geometry = EpochGeometryV0::new(active_set.epoch(), parameters)?;
    if geometry.expected_block_kind(header.height())? != header.block_kind() {
        return Err(crate::ValidationError::InvalidEpochTransition(
            "historical block geometry",
        ));
    }
    if header.parent_id() != parent.id()
        || header.height() != parent.height().checked_next()?
        || header.genesis_hash() != parent.genesis_hash()
        || header.chain_id() != parent.chain_id()
        || header.protocol_version() != parent.protocol_version()
    {
        return Err(crate::ValidationError::InvalidBlock(
            "historical header link",
        ));
    }
    validate_timestamp_step(parent.timestamp_ms(), header.timestamp_ms(), parameters)?;
    if header.block_kind() == BlockKind::EpochHandoff {
        if parent.block_kind() != BlockKind::EpochSeal2
            || header.epoch().get()
                != parent.epoch().get().checked_add(1).ok_or(
                    crate::ValidationError::ArithmeticOverflow("historical epoch"),
                )?
        {
            return Err(crate::ValidationError::InvalidEpochTransition(
                "historical handoff geometry",
            ));
        }
        return Ok(());
    }
    validate_header_set_binding(parent, active_set)?;
    validate_parameters_binding(parent, active_set, parameters)?;
    if header.epoch() != parent.epoch()
        || header.view() <= parent.view()
        || geometry.expected_block_kind(parent.height())? != parent.block_kind()
    {
        return Err(crate::ValidationError::InvalidEpochTransition(
            "historical block geometry",
        ));
    }
    if matches!(
        header.block_kind(),
        BlockKind::EpochSeal1 | BlockKind::EpochSeal2
    ) {
        let payload = OrderedRootV0::from_items::<&[u8]>(RootKind::Payload, &[])?.digest();
        let receipts = OrderedRootV0::from_items::<&[u8]>(RootKind::Receipts, &[])?.digest();
        let evidence = OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])?.digest();
        if header.payload_root().as_bytes() != &payload
            || header.receipts_root().as_bytes() != &receipts
            || header.evidence_root().as_bytes() != &evidence
            || header.state_root() != parent.state_root()
            || header.next_epoch_commitment_hash() != parent.next_epoch_commitment_hash()
        {
            return Err(crate::ValidationError::InvalidEpochTransition(
                "historical seal roots",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockId, ChainId, ConsensusPublicKey, Epoch, EvidenceRoot, GenesisHash, Height,
        NextEpochCommitmentHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot,
        Validator, ValidatorId, View, VotingPower,
    };

    fn set(epoch: u64, parameters: &ConsensusParametersV0) -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([9; 32]),
            ChainId::from_static("historical-links"),
            ProtocolVersion::V0,
            Epoch::new(epoch),
            parameters.hash(),
            [b'a', b'b', b'c', b'd']
                .into_iter()
                .map(|id| {
                    Validator::new(
                        ValidatorId::from_bytes(&[id]).unwrap(),
                        ConsensusPublicKey::new([id; 32]),
                        VotingPower::new(1).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn header(
        set: &ValidatorSet,
        kind: BlockKind,
        height: u64,
        view: u64,
        parent: BlockId,
        time: u64,
        leader: usize,
        state: u8,
    ) -> BlockHeader {
        BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            kind,
            parent,
            set.validators()[leader].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Payload, &[])
                    .unwrap()
                    .digest(),
            ),
            StateRoot::new([state; 32]),
            ReceiptsRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Receipts, &[])
                    .unwrap()
                    .digest(),
            ),
            EvidenceRoot::new(
                OrderedRootV0::from_items::<&[u8]>(RootKind::Evidence, &[])
                    .unwrap()
                    .digest(),
            ),
            time,
            if matches!(kind, BlockKind::Regular | BlockKind::EpochHandoff) {
                None
            } else {
                Some(NextEpochCommitmentHash::new([7; 32]))
            },
        )
        .unwrap()
    }

    #[test]
    fn historical_links_allow_skipped_views_but_bind_leader_and_time() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = set(0, &parameters);
        let parent = header(
            &set,
            BlockKind::Regular,
            1,
            1,
            BlockId::new([3; 32]),
            100,
            0,
            4,
        );
        let maximum = parent.timestamp_ms() + parameters.max_block_time_step_ms();
        let next = header(&set, BlockKind::Regular, 2, 4, parent.id(), maximum, 3, 5);
        assert!(validate_historical_header_link_v1(&next, &parent, &set, &parameters).is_ok());
        for bad in [
            header(&set, BlockKind::Regular, 2, 4, parent.id(), maximum, 0, 5),
            header(&set, BlockKind::Regular, 2, 1, parent.id(), 101, 0, 5),
            header(
                &set,
                BlockKind::Regular,
                2,
                4,
                parent.id(),
                maximum + 1,
                3,
                5,
            ),
            header(&set, BlockKind::Regular, 2, 4, parent.id(), 100, 3, 5),
            header(&set, BlockKind::Regular, 3, 4, parent.id(), 101, 3, 5),
            header(
                &set,
                BlockKind::Regular,
                2,
                4,
                BlockId::new([3; 32]),
                101,
                3,
                5,
            ),
        ] {
            assert!(validate_historical_header_link_v1(&bad, &parent, &set, &parameters).is_err());
        }
    }

    #[test]
    fn historical_handoff_uses_new_parameters_and_leader_at_its_scheduled_height() {
        let old = ConsensusParametersV0::reference_shadow_v0();
        let mut fields = old.fields();
        fields.max_block_time_step_ms = 2;
        let new = ConsensusParametersV0::new(fields).unwrap();
        let old_set = set(0, &old);
        let new_set = set(1, &new);
        let parent = header(
            &old_set,
            BlockKind::EpochSeal2,
            10_000,
            42,
            BlockId::new([3; 32]),
            100,
            1,
            4,
        );
        let first = header(
            &new_set,
            BlockKind::EpochHandoff,
            10_001,
            3,
            parent.id(),
            102,
            2,
            5,
        );
        assert!(validate_historical_header_link_v1(&first, &parent, &new_set, &new).is_ok());
        assert!(validate_historical_header_link_v1(&first, &parent, &old_set, &old).is_err());
        for bad in [
            header(
                &new_set,
                BlockKind::EpochHandoff,
                10_001,
                3,
                parent.id(),
                103,
                2,
                5,
            ),
            header(
                &new_set,
                BlockKind::EpochHandoff,
                10_001,
                3,
                parent.id(),
                102,
                0,
                5,
            ),
            header(
                &new_set,
                BlockKind::Regular,
                10_001,
                3,
                parent.id(),
                102,
                2,
                5,
            ),
        ] {
            assert!(validate_historical_header_link_v1(&bad, &parent, &new_set, &new).is_err());
        }
        let wrong_parent = header(
            &old_set,
            BlockKind::EpochSeal2,
            9_999,
            42,
            BlockId::new([3; 32]),
            100,
            1,
            4,
        );
        let wrong_first = header(
            &new_set,
            BlockKind::EpochHandoff,
            10_000,
            3,
            wrong_parent.id(),
            102,
            2,
            5,
        );
        assert!(
            validate_historical_header_link_v1(&wrong_first, &wrong_parent, &new_set, &new)
                .is_err()
        );
    }

    #[test]
    fn historical_seals_carry_checkpoint_state_without_application_execution() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = set(0, &parameters);
        let checkpoint = header(
            &set,
            BlockKind::EpochCheckpoint,
            9_998,
            40,
            BlockId::new([3; 32]),
            100,
            3,
            4,
        );
        let seal = header(
            &set,
            BlockKind::EpochSeal1,
            9_999,
            42,
            checkpoint.id(),
            101,
            1,
            4,
        );
        assert!(validate_historical_header_link_v1(&seal, &checkpoint, &set, &parameters).is_ok());
        let changed = header(
            &set,
            BlockKind::EpochSeal1,
            9_999,
            42,
            checkpoint.id(),
            101,
            1,
            5,
        );
        assert!(
            validate_historical_header_link_v1(&changed, &checkpoint, &set, &parameters).is_err()
        );
    }
}
