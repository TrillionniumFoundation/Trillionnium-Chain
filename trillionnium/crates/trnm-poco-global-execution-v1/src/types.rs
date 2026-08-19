use borsh::{BorshDeserialize, BorshSerialize};
use trnm_poco_agent_market_v1::KernelCommandV1;
use trnm_poco_consumption_settlement_v1::ConsumptionSettlementCommandV1;
use trnm_poco_da_v1::{AvailabilityCertificateIdV1, BatchIdV1, DaObligationIdV1};
use trnm_poco_mvcc_fee_v1::MvccBlockV1;
use trnm_poco_verify_challenge_v1::VerifyCommandV1;

#[derive(
    Clone, Copy, Debug, Default, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd,
)]
pub struct Hash32V1(pub [u8; 32]);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CandidateExecutionContextV1 {
    pub schema_version: u16,
    pub chain_id: String,
    pub genesis_hash: Hash32V1,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
}

/// One strictly decoded candidate batch carried as the sole item in a local
/// certified TransactionBatch.
///
/// This is intentionally not named `AgentTransactionV1`: that normative wire
/// remains draft and unfrozen.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct GlobalExecutionBatchV1 {
    pub schema_version: u16,
    pub context: CandidateExecutionContextV1,
    /// Height of the candidate Order header which carries this execution.
    pub candidate_height: u64,
    /// Domain-addressed Order header ID, never the MVCC-local block ID.
    pub candidate_block_id: Hash32V1,
    pub agent_market_commands: Vec<KernelCommandV1>,
    pub verify_challenge_commands: Vec<VerifyCommandV1>,
    pub mvcc_fee_block: MvccBlockV1,
    pub consumption_settlement_commands: Vec<ConsumptionSettlementCommandV1>,
}

impl GlobalExecutionBatchV1 {
    /// Returns the plane-local MVCC execution identity already committed by
    /// the exact DA batch bytes. This identity intentionally differs from the
    /// candidate Order block ID above.
    pub const fn mvcc_execution_block_id(&self) -> Hash32V1 {
        Hash32V1(self.mvcc_fee_block.block_id.0)
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct PreVoteProposalV1 {
    pub schema_version: u16,
    pub context: CandidateExecutionContextV1,
    pub scope: Hash32V1,
    pub expected_checkpoint_generation: u64,
    pub expected_checkpoint_checksum: Hash32V1,
    /// Exact candidate Order height selected by consensus.
    pub candidate_height: u64,
    /// Exact domain-addressed Order header ID selected by consensus.
    pub candidate_block_id: Hash32V1,
    pub batch_id: BatchIdV1,
    pub availability_certificate_id: AvailabilityCertificateIdV1,
    pub expected_candidate_composite_root: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct CandidateCompositeCommitmentBodyV1 {
    pub schema_version: u16,
    pub context: CandidateExecutionContextV1,
    pub candidate_height: u64,
    pub candidate_block_id: Hash32V1,
    pub source_cut_digest: Hash32V1,
    pub da_batch_id: BatchIdV1,
    pub da_certificate_id: AvailabilityCertificateIdV1,
    pub da_obligation_id: DaObligationIdV1,
    pub da_obligation_version: u64,
    pub retrieved_batch_digest: Hash32V1,
    pub agent_market_candidate_root: Hash32V1,
    pub agent_market_receipts_root: Hash32V1,
    pub verify_challenge_candidate_root: Hash32V1,
    pub verify_challenge_receipts_root: Hash32V1,
    pub mvcc_fee_candidate_root: Hash32V1,
    pub mvcc_receipts_root: Hash32V1,
    pub mvcc_resource_totals_root: Hash32V1,
    pub mvcc_fee_deltas_root: Hash32V1,
    pub mvcc_resolution_root: Hash32V1,
    pub consumption_settlement_candidate_root: Hash32V1,
    pub consumption_settlement_receipts_root: Hash32V1,
}

/// Domain-separated commitment to the bounded candidate execution result.
///
/// It is not the normative protocol application JMT root and must never be
/// substituted for one.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CandidateCompositeCommitmentV1 {
    pub(crate) body: CandidateCompositeCommitmentBodyV1,
    pub(crate) candidate_composite_root: Hash32V1,
}

impl CandidateCompositeCommitmentV1 {
    pub const fn candidate_composite_root(&self) -> Hash32V1 {
        self.candidate_composite_root
    }

    pub const fn candidate_height(&self) -> u64 {
        self.body.candidate_height
    }

    pub const fn candidate_block_id(&self) -> Hash32V1 {
        self.body.candidate_block_id
    }

    pub const fn source_cut_digest(&self) -> Hash32V1 {
        self.body.source_cut_digest
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct PlaneHeadV1 {
    pub plane_tag: u8,
    pub store_schema_version: u16,
    pub store_id: Hash32V1,
    pub sequence_or_height: u64,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub state_or_metadata_root: Hash32V1,
    pub journal_root: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct SourceCutV1 {
    pub schema_version: u16,
    pub context: CandidateExecutionContextV1,
    pub plane_heads: Vec<PlaneHeadV1>,
    pub digest: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct PlaneTerminalFactsV1 {
    pub plane_tag: u8,
    pub store_id: Hash32V1,
    pub source_sequence_or_height: u64,
    pub source_state_or_metadata_root: Hash32V1,
    pub source_journal_root: Hash32V1,
    pub terminal_sequence_or_height: u64,
    pub terminal_order_height: u64,
    pub terminal_order_block_id: Hash32V1,
    pub terminal_state_or_metadata_root: Hash32V1,
    pub terminal_receipts_root: Hash32V1,
    pub terminal_journal_root: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct WholeNodeFinalizationBodyV1 {
    pub schema_version: u16,
    pub context: CandidateExecutionContextV1,
    pub scope: Hash32V1,
    pub prepared_checkpoint_generation: u64,
    pub prepared_checkpoint_checksum: Hash32V1,
    pub candidate_height: u64,
    pub candidate_block_id: Hash32V1,
    pub candidate_composite_root: Hash32V1,
    pub source_cut_digest: Hash32V1,
    pub plane_terminals: Vec<PlaneTerminalFactsV1>,
}

/// Candidate-local commitment to one externally authenticated terminal cut.
///
/// This is neither an application JMT root nor an Order `post_state_root`.
/// Only the crate-owned finalization carrier can authorize its persistence.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct WholeNodeFinalExecutionCommitmentV1 {
    pub(crate) body: WholeNodeFinalizationBodyV1,
    pub(crate) final_execution_root: Hash32V1,
}

impl WholeNodeFinalExecutionCommitmentV1 {
    pub const fn final_execution_root(&self) -> Hash32V1 {
        self.final_execution_root
    }

    pub const fn candidate_height(&self) -> u64 {
        self.body.candidate_height
    }

    pub const fn candidate_block_id(&self) -> Hash32V1 {
        self.body.candidate_block_id
    }

    pub const fn candidate_composite_root(&self) -> Hash32V1 {
        self.body.candidate_composite_root
    }

    pub const fn prepared_checkpoint_generation(&self) -> u64 {
        self.body.prepared_checkpoint_generation
    }

    pub const fn prepared_checkpoint_checksum(&self) -> Hash32V1 {
        self.body.prepared_checkpoint_checksum
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct CheckpointBodyV1 {
    pub schema_version: u16,
    pub scope: Hash32V1,
    pub generation: u64,
    pub predecessor_checksum: Hash32V1,
    pub source_cut: SourceCutV1,
    pub prepared: Option<CandidateCompositeCommitmentV1>,
    pub finalized: Option<WholeNodeFinalExecutionCommitmentV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub(crate) struct CheckpointRecordV1 {
    pub body: CheckpointBodyV1,
    pub checksum: Hash32V1,
}
