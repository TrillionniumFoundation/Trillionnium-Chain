//! Inert dual-parent application requests. The execution owner must separately
//! match an authenticated epoch edge; constructing or decoding these fields is
//! not handoff, execution, or commit authority.

use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeExpectedBlockCommitmentsV0, ValidatorSetIdV0, MAX_BLOCK_BYTES_V0,
    MAX_BLOCK_TRANSACTIONS_V0,
};

/// First new-epoch input: the application parent remains checkpoint C while
/// the consensus parent is seal-2 C+2. No application head is invented at C+2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEpochBlockPreviewRequestV1 {
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    application_parent: ApplicationHeadV0,
    consensus_parent_id: BlockIdV0,
    consensus_parent_height: HeightV0,
    edge_binding: Hash32V0,
    height: HeightV0,
    timestamp_ms: u64,
    active_validator_set_id: ValidatorSetIdV0,
    transactions: Vec<Vec<u8>>,
    transaction_bytes: usize,
}

/// Exact computed epoch artifact. Like its ordinary counterpart this is inert
/// transport/storage data; only the durable owner can attest a persisted P.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExecutedEpochBlockV1 {
    request: NativeEpochBlockExecutionRequestV1,
    receipts: Vec<crate::NativeExecutionReceiptV0>,
}

impl NativeExecutedEpochBlockV1 {
    pub fn new(
        request: NativeEpochBlockExecutionRequestV1,
        computed: NativeExpectedBlockCommitmentsV0,
        receipts: Vec<crate::NativeExecutionReceiptV0>,
    ) -> NativeBoundaryResultV0<Self> {
        if computed != request.expected()
            || receipts.len() != request.preview().transactions().len()
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "epoch_executed.commitments",
            ));
        }
        for (index, receipt) in receipts.iter().enumerate() {
            if usize::try_from(receipt.transaction_index()).ok() != Some(index) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::NonContiguous,
                    "epoch_executed.receipt_indices",
                ));
            }
        }
        Ok(Self { request, receipts })
    }
    pub const fn request(&self) -> &NativeEpochBlockExecutionRequestV1 {
        &self.request
    }
    pub fn receipts(&self) -> &[crate::NativeExecutionReceiptV0] {
        &self.receipts
    }
}

impl NativeEpochBlockPreviewRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        application_parent: ApplicationHeadV0,
        consensus_parent_id: BlockIdV0,
        consensus_parent_height: HeightV0,
        edge_binding: Hash32V0,
        height: HeightV0,
        timestamp_ms: u64,
        active_validator_set_id: ValidatorSetIdV0,
        transactions: Vec<Vec<u8>>,
    ) -> NativeBoundaryResultV0<Self> {
        let checkpoint = application_parent.height().get();
        if checkpoint.checked_add(2) != Some(consensus_parent_height.get())
            || checkpoint.checked_add(3) != Some(height.get())
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "epoch_execution.geometry",
            ));
        }
        if consensus_parent_id == application_parent.block_id() {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "epoch_execution.distinct_parents",
            ));
        }
        edge_binding.require_nonzero("epoch_execution.edge_binding")?;
        if transactions.len() > MAX_BLOCK_TRANSACTIONS_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "epoch_execution.transactions",
            ));
        }
        let mut transaction_bytes = 4usize;
        for transaction in &transactions {
            transaction_bytes = transaction_bytes
                .checked_add(4)
                .and_then(|total| total.checked_add(transaction.len()))
                .ok_or_else(|| {
                    error(
                        NativeBoundaryErrorCodeV0::Overflow,
                        "epoch_execution.transaction_bytes",
                    )
                })?;
            if transaction_bytes > MAX_BLOCK_BYTES_V0 {
                return Err(error(
                    NativeBoundaryErrorCodeV0::TooLong,
                    "epoch_execution.transaction_bytes",
                ));
            }
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            application_parent,
            consensus_parent_id,
            consensus_parent_height,
            edge_binding,
            height,
            timestamp_ms,
            active_validator_set_id,
            transactions,
            transaction_bytes,
        })
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }
    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }
    pub const fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.application_parent
    }
    pub const fn consensus_parent_id(&self) -> BlockIdV0 {
        self.consensus_parent_id
    }
    pub const fn consensus_parent_height(&self) -> HeightV0 {
        self.consensus_parent_height
    }
    pub const fn edge_binding(&self) -> Hash32V0 {
        self.edge_binding
    }
    pub const fn height(&self) -> HeightV0 {
        self.height
    }
    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
    pub const fn active_validator_set_id(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id
    }
    pub fn transactions(&self) -> &[Vec<u8>] {
        &self.transactions
    }
    pub const fn transaction_bytes(&self) -> usize {
        self.transaction_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEpochBlockExecutionRequestV1 {
    preview: NativeEpochBlockPreviewRequestV1,
    block_id: BlockIdV0,
    expected: NativeExpectedBlockCommitmentsV0,
}

impl NativeEpochBlockExecutionRequestV1 {
    pub fn new(
        preview: NativeEpochBlockPreviewRequestV1,
        block_id: BlockIdV0,
        expected: NativeExpectedBlockCommitmentsV0,
    ) -> NativeBoundaryResultV0<Self> {
        if block_id == preview.application_parent().block_id()
            || block_id == preview.consensus_parent_id()
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "epoch_execution.block_id",
            ));
        }
        Ok(Self {
            preview,
            block_id,
            expected,
        })
    }
    pub const fn preview(&self) -> &NativeEpochBlockPreviewRequestV1 {
        &self.preview
    }
    pub const fn block_id(&self) -> BlockIdV0 {
        self.block_id
    }
    pub const fn expected(&self) -> NativeExpectedBlockCommitmentsV0 {
        self.expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationCommitIdV0, ReceiptsRootV0, StateRootV0};

    fn request(
        checkpoint: u64,
        terminal: u64,
        target: u64,
        edge: [u8; 32],
        txs: Vec<Vec<u8>>,
    ) -> NativeBoundaryResultV0<NativeEpochBlockPreviewRequestV1> {
        NativeEpochBlockPreviewRequestV1::new(
            ChainIdV0::new("epoch-boundary-test").unwrap(),
            GenesisHashV0::new([1; 32]).unwrap(),
            ApplicationHeadV0::new(
                HeightV0::new(checkpoint),
                BlockIdV0::new([2; 32]).unwrap(),
                StateRootV0::new([3; 32]).unwrap(),
                ApplicationCommitIdV0::new([4; 32]).unwrap(),
            ),
            BlockIdV0::new([5; 32]).unwrap(),
            HeightV0::new(terminal),
            Hash32V0::new(edge),
            HeightV0::new(target),
            42,
            ValidatorSetIdV0::new([6; 32]).unwrap(),
            txs,
        )
    }

    #[test]
    fn dual_parent_geometry_rejects_skips_overflow_and_missing_binding() {
        let valid = request(8, 10, 11, [7; 32], vec![vec![1, 2, 3]]).unwrap();
        assert_eq!(valid.application_parent().height().get(), 8);
        assert_eq!(valid.consensus_parent_height().get(), 10);
        assert_eq!(valid.height().get(), 11);
        assert_eq!(valid.transaction_bytes(), 11);
        for (checkpoint, terminal, target) in [(8, 9, 11), (8, 10, 12), (u64::MAX - 1, u64::MAX, 0)]
        {
            assert_eq!(
                request(checkpoint, terminal, target, [7; 32], vec![])
                    .unwrap_err()
                    .code(),
                NativeBoundaryErrorCodeV0::NonContiguous
            );
        }
        assert!(request(8, 10, 11, [0; 32], vec![]).is_err());
    }

    #[test]
    fn epoch_artifact_preserves_both_parents_and_rejects_cross_codec_or_truncated_bytes() {
        let preview = request(
            8,
            10,
            11,
            [7; 32],
            vec![b"exact signed native bytes".to_vec()],
        )
        .unwrap();
        let expected = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new([8; 32]),
            StateRootV0::new([9; 32]).unwrap(),
            ReceiptsRootV0::new([10; 32]).unwrap(),
            Hash32V0::new([11; 32]),
        )
        .unwrap();
        let execution = NativeEpochBlockExecutionRequestV1::new(
            preview,
            BlockIdV0::new([12; 32]).unwrap(),
            expected,
        )
        .unwrap();
        let receipt = crate::NativeExecutionReceiptV0::new(
            0,
            Hash32V0::new([13; 32]),
            17,
            19,
            vec![],
            Hash32V0::new([14; 32]),
        )
        .unwrap();
        let executed =
            NativeExecutedEpochBlockV1::new(execution.clone(), expected, vec![receipt]).unwrap();
        assert!(NativeExecutedEpochBlockV1::new(execution, expected, vec![]).is_err());
        let bytes = crate::encode_native_executed_epoch_block_artifact_v1(&executed).unwrap();
        assert_eq!(
            crate::decode_native_executed_epoch_block_artifact_v1(&bytes).unwrap(),
            executed
        );
        assert!(crate::decode_native_executed_block_artifact_v0(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(crate::decode_native_executed_epoch_block_artifact_v1(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(crate::decode_native_executed_epoch_block_artifact_v1(&trailing).is_err());
        let mut wrong_version = bytes.clone();
        wrong_version[crate::NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1.len() + 7] = 0;
        assert!(crate::decode_native_executed_epoch_block_artifact_v1(&wrong_version).is_err());
        // Changing target geometry cannot be smuggled through the decoder.
        let mut wrong_geometry = bytes;
        let target_offset = crate::NATIVE_EXECUTED_EPOCH_BLOCK_ARTIFACT_DOMAIN_V1.len()
            + 8
            + 4
            + "epoch-boundary-test".len()
            + 32
            + 8
            + 32 * 3
            + 8
            + 32 * 2
            + 32;
        wrong_geometry[target_offset + 7] = 12;
        assert!(crate::decode_native_executed_epoch_block_artifact_v1(&wrong_geometry).is_err());
    }

    #[test]
    fn dual_parent_requests_keep_exact_encoded_block_byte_bounds() {
        assert!(request(8, 10, 11, [7; 32], vec![vec![0; MAX_BLOCK_BYTES_V0 - 8]]).is_ok());
        assert_eq!(
            request(8, 10, 11, [7; 32], vec![vec![0; MAX_BLOCK_BYTES_V0 - 7]])
                .unwrap_err()
                .code(),
            NativeBoundaryErrorCodeV0::TooLong
        );
        assert!(request(
            8,
            10,
            11,
            [7; 32],
            vec![vec![0; MAX_BLOCK_BYTES_V0 / 2 - 6]; 2]
        )
        .is_ok());
        assert_eq!(
            request(
                8,
                10,
                11,
                [7; 32],
                vec![vec![0; MAX_BLOCK_BYTES_V0 / 2 - 5]; 2]
            )
            .unwrap_err()
            .code(),
            NativeBoundaryErrorCodeV0::TooLong
        );
        let preview = request(8, 10, 11, [7; 32], vec![]).unwrap();
        let expected = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new([8; 32]),
            StateRootV0::new([9; 32]).unwrap(),
            ReceiptsRootV0::new([10; 32]).unwrap(),
            Hash32V0::new([11; 32]),
        )
        .unwrap();
        for parent_id in [
            preview.application_parent().block_id(),
            preview.consensus_parent_id(),
        ] {
            assert_eq!(
                NativeEpochBlockExecutionRequestV1::new(preview.clone(), parent_id, expected)
                    .unwrap_err()
                    .code(),
                NativeBoundaryErrorCodeV0::InvalidTransition
            );
        }
    }
}
