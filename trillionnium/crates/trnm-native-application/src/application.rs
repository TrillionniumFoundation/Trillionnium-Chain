use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    execution::NativeExecutionReceiptV0,
    primitives::{
        ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, ReceiptsRootV0,
        StateRootV0, ValidatorSetIdV0,
    },
    recovery::{NativeApplicationRecoveryRequestV0, NativeApplicationRecoveryResultV0},
    snapshot::{
        NativeSnapshotManifestV0, NativeSnapshotRequestV0, NativeStateProofRequestV0,
        NativeStateProofV0,
    },
    validator::{NativeValidatorSetTransitionV0, NativeValidatorSetV0},
};

pub const MAX_BLOCK_TRANSACTIONS_V0: usize = u32::MAX as usize;
pub const MAX_BLOCK_BYTES_V0: usize = 4 * 1024 * 1024;
pub const MAX_INVALID_CODE_BYTES_V0: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExpectedBlockCommitmentsV0 {
    payload_root: Hash32V0,
    post_state_root: StateRootV0,
    receipts_root: ReceiptsRootV0,
    evidence_root: Hash32V0,
}

impl NativeExpectedBlockCommitmentsV0 {
    pub fn new(
        payload_root: Hash32V0,
        post_state_root: StateRootV0,
        receipts_root: ReceiptsRootV0,
        evidence_root: Hash32V0,
    ) -> NativeBoundaryResultV0<Self> {
        Ok(Self {
            payload_root: payload_root.require_nonzero("block_commitments.payload_root")?,
            post_state_root,
            receipts_root,
            evidence_root: evidence_root.require_nonzero("block_commitments.evidence_root")?,
        })
    }

    pub const fn payload_root(self) -> Hash32V0 {
        self.payload_root
    }

    pub const fn post_state_root(self) -> StateRootV0 {
        self.post_state_root
    }

    pub const fn receipts_root(self) -> ReceiptsRootV0 {
        self.receipts_root
    }

    pub const fn evidence_root(self) -> Hash32V0 {
        self.evidence_root
    }
}

/// Exact frozen-v0 block body and authenticated parent supplied for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockExecutionRequestV0 {
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    parent: ApplicationHeadV0,
    block_id: BlockIdV0,
    height: HeightV0,
    timestamp_ms: u64,
    active_validator_set_id: ValidatorSetIdV0,
    transactions: Vec<Vec<u8>>,
    transaction_bytes: usize,
    expected: NativeExpectedBlockCommitmentsV0,
}

impl NativeBlockExecutionRequestV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        parent: ApplicationHeadV0,
        block_id: BlockIdV0,
        height: HeightV0,
        timestamp_ms: u64,
        active_validator_set_id: ValidatorSetIdV0,
        transactions: Vec<Vec<u8>>,
        expected: NativeExpectedBlockCommitmentsV0,
    ) -> NativeBoundaryResultV0<Self> {
        if height != parent.height().checked_next()? {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "block_execution.height",
            ));
        }
        if block_id == parent.block_id() {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "block_execution.block_id",
            ));
        }
        if transactions.len() > MAX_BLOCK_TRANSACTIONS_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "block_execution.transactions",
            ));
        }
        let mut transaction_bytes = 4usize;
        for transaction in &transactions {
            transaction_bytes = transaction_bytes
                .checked_add(4)
                .and_then(|value| value.checked_add(transaction.len()))
                .ok_or_else(|| {
                    error(
                        NativeBoundaryErrorCodeV0::Overflow,
                        "block_execution.transaction_bytes",
                    )
                })?;
            if transaction_bytes > MAX_BLOCK_BYTES_V0 {
                return Err(error(
                    NativeBoundaryErrorCodeV0::TooLong,
                    "block_execution.transaction_bytes",
                ));
            }
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            parent,
            block_id,
            height,
            timestamp_ms,
            active_validator_set_id,
            transactions,
            transaction_bytes,
            expected,
        })
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }

    pub const fn parent(&self) -> &ApplicationHeadV0 {
        &self.parent
    }

    pub const fn block_id(&self) -> BlockIdV0 {
        self.block_id
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

    pub const fn expected(&self) -> NativeExpectedBlockCommitmentsV0 {
        self.expected
    }
}

/// Successful execution capability bound to one exact request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExecutedBlockV0 {
    request: NativeBlockExecutionRequestV0,
    receipts: Vec<NativeExecutionReceiptV0>,
}

impl NativeExecutedBlockV0 {
    pub fn new(
        request: NativeBlockExecutionRequestV0,
        computed_payload_root: Hash32V0,
        computed_post_state_root: StateRootV0,
        computed_receipts_root: ReceiptsRootV0,
        computed_evidence_root: Hash32V0,
        receipts: Vec<NativeExecutionReceiptV0>,
    ) -> NativeBoundaryResultV0<Self> {
        if computed_payload_root != request.expected().payload_root()
            || computed_post_state_root != request.expected().post_state_root()
            || computed_receipts_root != request.expected().receipts_root()
            || computed_evidence_root != request.expected().evidence_root()
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "executed_block.commitments",
            ));
        }
        if receipts.len() != request.transactions().len() {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "executed_block.receipts",
            ));
        }
        for (expected_index, receipt) in receipts.iter().enumerate() {
            if usize::try_from(receipt.transaction_index()).ok() != Some(expected_index) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::NonContiguous,
                    "executed_block.receipt_indices",
                ));
            }
        }
        Ok(Self { request, receipts })
    }

    pub const fn request(&self) -> &NativeBlockExecutionRequestV0 {
        &self.request
    }

    pub fn receipts(&self) -> &[NativeExecutionReceiptV0] {
        &self.receipts
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDeterministicInvalidV0 {
    request: NativeBlockExecutionRequestV0,
    code: String,
}

impl NativeDeterministicInvalidV0 {
    pub fn new(
        request: &NativeBlockExecutionRequestV0,
        code: impl Into<String>,
    ) -> NativeBoundaryResultV0<Self> {
        let code = code.into();
        if code.is_empty() {
            return Err(error(
                NativeBoundaryErrorCodeV0::Empty,
                "deterministic_invalid.code",
            ));
        }
        if code.len() > MAX_INVALID_CODE_BYTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooLong,
                "deterministic_invalid.code",
            ));
        }
        if !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "deterministic_invalid.code",
            ));
        }
        Ok(Self {
            request: request.clone(),
            code,
        })
    }

    pub const fn request(&self) -> &NativeBlockExecutionRequestV0 {
        &self.request
    }

    pub const fn block_id(&self) -> BlockIdV0 {
        self.request.block_id()
    }

    pub const fn height(&self) -> HeightV0 {
        self.request.height()
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeUnavailableReasonV0 {
    ParentStateUnavailable,
    AuthenticatedStateUnavailable,
    HostResourceUnavailable,
    RecoveryInProgress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeUnavailableV0 {
    request: NativeBlockExecutionRequestV0,
    reason: NativeUnavailableReasonV0,
}

impl NativeUnavailableV0 {
    pub const fn request(&self) -> &NativeBlockExecutionRequestV0 {
        &self.request
    }

    pub const fn reason(&self) -> NativeUnavailableReasonV0 {
        self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeBlockExecutionResultV0 {
    Valid(Box<NativeExecutedBlockV0>),
    DeterministicallyInvalid(NativeDeterministicInvalidV0),
    Unavailable(NativeUnavailableV0),
}

impl NativeBlockExecutionResultV0 {
    pub fn valid(executed: NativeExecutedBlockV0) -> Self {
        Self::Valid(Box::new(executed))
    }

    pub fn unavailable(
        request: &NativeBlockExecutionRequestV0,
        reason: NativeUnavailableReasonV0,
    ) -> Self {
        Self::Unavailable(NativeUnavailableV0 {
            request: request.clone(),
            reason,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationGenesisRequestV0 {
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    chain_descriptor_hash: Hash32V0,
    signer_policy_commitment: Hash32V0,
    initial_state_root: StateRootV0,
    initial_validator_set: NativeValidatorSetV0,
}

impl NativeApplicationGenesisRequestV0 {
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        chain_descriptor_hash: Hash32V0,
        signer_policy_commitment: Hash32V0,
        initial_state_root: StateRootV0,
        initial_validator_set: NativeValidatorSetV0,
    ) -> NativeBoundaryResultV0<Self> {
        Ok(Self {
            chain_id,
            genesis_hash,
            chain_descriptor_hash: chain_descriptor_hash
                .require_nonzero("genesis.chain_descriptor_hash")?,
            signer_policy_commitment: signer_policy_commitment
                .require_nonzero("genesis.signer_policy_commitment")?,
            initial_state_root,
            initial_validator_set,
        })
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }

    pub const fn chain_descriptor_hash(&self) -> Hash32V0 {
        self.chain_descriptor_hash
    }

    pub const fn signer_policy_commitment(&self) -> Hash32V0 {
        self.signer_policy_commitment
    }

    pub const fn initial_state_root(&self) -> StateRootV0 {
        self.initial_state_root
    }

    pub const fn initial_validator_set(&self) -> &NativeValidatorSetV0 {
        &self.initial_validator_set
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationGenesisResultV0 {
    request: NativeApplicationGenesisRequestV0,
    head: ApplicationHeadV0,
    active_validator_set_id: ValidatorSetIdV0,
}

impl NativeApplicationGenesisResultV0 {
    pub fn new(
        request: &NativeApplicationGenesisRequestV0,
        head: ApplicationHeadV0,
        active_validator_set_id: ValidatorSetIdV0,
    ) -> NativeBoundaryResultV0<Self> {
        if head.height() != HeightV0::GENESIS
            || head.state_root() != request.initial_state_root()
            || active_validator_set_id != request.initial_validator_set().set_id()
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "genesis.result",
            ));
        }
        Ok(Self {
            request: request.clone(),
            head,
            active_validator_set_id,
        })
    }

    pub const fn request(&self) -> &NativeApplicationGenesisRequestV0 {
        &self.request
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub const fn active_validator_set_id(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationCommitRequestV0 {
    executed: NativeExecutedBlockV0,
}

impl NativeApplicationCommitRequestV0 {
    pub const fn new(executed: NativeExecutedBlockV0) -> Self {
        Self { executed }
    }

    pub const fn executed(&self) -> &NativeExecutedBlockV0 {
        &self.executed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplicationCommitResultV0 {
    request: NativeApplicationCommitRequestV0,
    head: ApplicationHeadV0,
    durable_sequence: u64,
    validator_transition: Option<NativeValidatorSetTransitionV0>,
}

impl NativeApplicationCommitResultV0 {
    pub fn new(
        request: &NativeApplicationCommitRequestV0,
        head: ApplicationHeadV0,
        durable_sequence: u64,
        validator_transition: Option<NativeValidatorSetTransitionV0>,
    ) -> NativeBoundaryResultV0<Self> {
        let execution = request.executed().request();
        if durable_sequence == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "commit.durable_sequence",
            ));
        }
        if head.height() != execution.height()
            || head.block_id() != execution.block_id()
            || head.state_root() != execution.expected().post_state_root()
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "commit.head",
            ));
        }
        if let Some(transition) = &validator_transition {
            if transition.current_set_id() != execution.active_validator_set_id()
                || transition.activation_height() <= head.height()
            {
                return Err(error(
                    NativeBoundaryErrorCodeV0::InvalidTransition,
                    "commit.validator_transition",
                ));
            }
        }
        Ok(Self {
            request: request.clone(),
            head,
            durable_sequence,
            validator_transition,
        })
    }

    pub const fn request(&self) -> &NativeApplicationCommitRequestV0 {
        &self.request
    }

    pub const fn executed(&self) -> &NativeExecutedBlockV0 {
        self.request.executed()
    }

    pub const fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub const fn durable_sequence(&self) -> u64 {
        self.durable_sequence
    }

    pub const fn validator_transition(&self) -> Option<&NativeValidatorSetTransitionV0> {
        self.validator_transition.as_ref()
    }
}

/// Host contract implemented by the native application store/engine.
pub trait NativeApplicationV0 {
    type Error;

    fn initialize(
        &self,
        request: NativeApplicationGenesisRequestV0,
    ) -> Result<NativeApplicationGenesisResultV0, Self::Error>;

    fn execute_block(
        &self,
        request: NativeBlockExecutionRequestV0,
    ) -> Result<NativeBlockExecutionResultV0, Self::Error>;

    fn commit_block(
        &self,
        request: NativeApplicationCommitRequestV0,
    ) -> Result<NativeApplicationCommitResultV0, Self::Error>;

    fn state_proof(
        &self,
        request: NativeStateProofRequestV0,
    ) -> Result<NativeStateProofV0, Self::Error>;

    fn snapshot(
        &self,
        request: NativeSnapshotRequestV0,
    ) -> Result<NativeSnapshotManifestV0, Self::Error>;

    fn recover(
        &self,
        request: NativeApplicationRecoveryRequestV0,
    ) -> Result<NativeApplicationRecoveryResultV0, Self::Error>;
}
