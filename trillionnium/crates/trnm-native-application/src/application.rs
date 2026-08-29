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

/// Maximum number of canonical finalization intents retained by the
/// host-neutral queue.  A process owner may choose a smaller bound, but may
/// never grow an unbounded queue from an unauthenticated caller.
pub const MAX_FINALIZATION_QUEUE_ENTRIES_V0: usize = 1024;

/// The complete identity of one application-finalization successor.
///
/// This value is deliberately independent of Core/Safety types.  A consuming
/// owner must join it to a live Core-issued permit before applying it.  The
/// body, overlay and JMT-plan digests are carried explicitly so a height/root
/// tuple can never stand in for the authenticated source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationIntentV0 {
    parent: ApplicationHeadV0,
    target: ApplicationHeadV0,
    proof_id: Hash32V0,
    overlay_checksum: Hash32V0,
    body_digest: Hash32V0,
    jmt_plan_digest: Hash32V0,
}

impl NativeFinalizationIntentV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: ApplicationHeadV0,
        target: ApplicationHeadV0,
        proof_id: Hash32V0,
        overlay_checksum: Hash32V0,
        body_digest: Hash32V0,
        jmt_plan_digest: Hash32V0,
    ) -> NativeBoundaryResultV0<Self> {
        if target.height() != parent.height().checked_next()? {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "finalization.target_height",
            ));
        }
        if target.block_id() == parent.block_id() {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "finalization.target_block_id",
            ));
        }
        Ok(Self {
            parent,
            target,
            proof_id: proof_id.require_nonzero("finalization.proof_id")?,
            overlay_checksum: overlay_checksum
                .require_nonzero("finalization.overlay_checksum")?,
            body_digest: body_digest.require_nonzero("finalization.body_digest")?,
            jmt_plan_digest: jmt_plan_digest
                .require_nonzero("finalization.jmt_plan_digest")?,
        })
    }

    pub const fn parent(&self) -> &ApplicationHeadV0 {
        &self.parent
    }

    pub const fn target(&self) -> &ApplicationHeadV0 {
        &self.target
    }

    pub const fn proof_id(&self) -> Hash32V0 {
        self.proof_id
    }

    pub const fn overlay_checksum(&self) -> Hash32V0 {
        self.overlay_checksum
    }

    pub const fn body_digest(&self) -> Hash32V0 {
        self.body_digest
    }

    pub const fn jmt_plan_digest(&self) -> Hash32V0 {
        self.jmt_plan_digest
    }
}

/// Fresh readback proving that one exact finalization intent was committed.
///
/// The JMT root is repeated rather than inferred from the target head.  This
/// forces a store adapter to report the root it actually read after commit and
/// lets the queue reject a post-state-root drift before acknowledging its
/// front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationApplyReadbackV0 {
    intent: NativeFinalizationIntentV0,
    committed_head: ApplicationHeadV0,
    jmt_root: StateRootV0,
    application_receipt_digest: Hash32V0,
    durable_sequence: u64,
}

impl NativeFinalizationApplyReadbackV0 {
    pub fn new(
        intent: NativeFinalizationIntentV0,
        committed_head: ApplicationHeadV0,
        jmt_root: StateRootV0,
        application_receipt_digest: Hash32V0,
        durable_sequence: u64,
    ) -> NativeBoundaryResultV0<Self> {
        if &committed_head != intent.target() || jmt_root != intent.target().state_root() {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization.readback.head",
            ));
        }
        if durable_sequence == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "finalization.readback.durable_sequence",
            ));
        }
        Ok(Self {
            intent,
            committed_head,
            jmt_root,
            application_receipt_digest: application_receipt_digest
                .require_nonzero("finalization.readback.receipt_digest")?,
            durable_sequence,
        })
    }

    pub const fn intent(&self) -> &NativeFinalizationIntentV0 {
        &self.intent
    }

    pub const fn committed_head(&self) -> &ApplicationHeadV0 {
        &self.committed_head
    }

    pub const fn jmt_root(&self) -> StateRootV0 {
        self.jmt_root
    }

    pub const fn application_receipt_digest(&self) -> Hash32V0 {
        self.application_receipt_digest
    }

    pub const fn durable_sequence(&self) -> u64 {
        self.durable_sequence
    }
}

/// A retained losing-fork record.  The reference digest is an inert handle
/// supplied by the caller; only an authenticated recovery owner should decide
/// which references are still live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationForkV0 {
    intent: NativeFinalizationIntentV0,
    reference_digest: Hash32V0,
}

impl NativeFinalizationForkV0 {
    pub fn new(
        intent: NativeFinalizationIntentV0,
        reference_digest: Hash32V0,
    ) -> NativeBoundaryResultV0<Self> {
        Ok(Self {
            intent,
            reference_digest: reference_digest
                .require_nonzero("finalization.fork.reference_digest")?,
        })
    }

    pub const fn intent(&self) -> &NativeFinalizationIntentV0 {
        &self.intent
    }

    pub const fn reference_digest(&self) -> Hash32V0 {
        self.reference_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFinalizationEnqueueOutcomeV0 {
    Queued,
    AlreadyQueued,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFinalizationApplyOutcomeV0 {
    NewlyCommitted(NativeFinalizationApplyReadbackV0),
    ExactReplay(NativeFinalizationApplyReadbackV0),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFinalizationRetryDispositionV0 {
    Pending,
    ExactCommitted(NativeFinalizationApplyReadbackV0),
}

/// Candidate-only application finalization queue.
///
/// The queue is intentionally a pure state machine.  It does not open a
/// database, issue a Core permit, or perform a JMT write.  A durable adapter
/// must first commit its rows and obtain a fresh
/// [`NativeFinalizationApplyReadbackV0`], then consume that readback here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationQueueV0 {
    committed_head: ApplicationHeadV0,
    pending: Vec<NativeFinalizationIntentV0>,
    history: Vec<NativeFinalizationApplyReadbackV0>,
    forks: Vec<NativeFinalizationForkV0>,
    capacity: usize,
}

impl NativeFinalizationQueueV0 {
    pub fn new(
        committed_head: ApplicationHeadV0,
        capacity: usize,
    ) -> NativeBoundaryResultV0<Self> {
        if capacity == 0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::ZeroValue,
                "finalization_queue.capacity",
            ));
        }
        if capacity > MAX_FINALIZATION_QUEUE_ENTRIES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "finalization_queue.capacity",
            ));
        }
        Ok(Self {
            committed_head,
            pending: Vec::new(),
            history: Vec::new(),
            forks: Vec::new(),
            capacity,
        })
    }

    pub const fn committed_head(&self) -> &ApplicationHeadV0 {
        &self.committed_head
    }

    pub fn pending(&self) -> &[NativeFinalizationIntentV0] {
        &self.pending
    }

    pub fn history(&self) -> &[NativeFinalizationApplyReadbackV0] {
        &self.history
    }

    pub fn forks(&self) -> &[NativeFinalizationForkV0] {
        &self.forks
    }

    pub fn front(&self) -> Option<&NativeFinalizationIntentV0> {
        self.pending.first()
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Appends one exact successor.  An exact retry is reported as
    /// `AlreadyQueued`; a same-target/different-identity collision is rejected
    /// instead of silently selecting a source by route or insertion order.
    pub fn enqueue(
        &mut self,
        intent: NativeFinalizationIntentV0,
    ) -> NativeBoundaryResultV0<NativeFinalizationEnqueueOutcomeV0> {
        self.validate_v0()?;
        if self.pending.contains(&intent)
            || self.history.iter().any(|entry| entry.intent() == &intent)
        {
            return Ok(NativeFinalizationEnqueueOutcomeV0::AlreadyQueued);
        }
        if self.forks.iter().any(|entry| entry.intent() == &intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::Duplicate,
                "finalization_queue.losing_fork",
            ));
        }
        if self.contains_conflicting_identity_v0(&intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_queue.identity",
            ));
        }
        let expected_parent = match self.pending.last() {
            Some(entry) => entry.target().clone(),
            None => self.committed_head.clone(),
        };
        if intent.parent() != &expected_parent {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "finalization_queue.parent",
            ));
        }
        if self.pending.len() >= self.capacity {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "finalization_queue.pending",
            ));
        }
        let mut next = self.clone();
        next.pending.push(intent);
        next.validate_v0()?;
        *self = next;
        Ok(NativeFinalizationEnqueueOutcomeV0::Queued)
    }

    /// Retains a competing branch without allowing it to become executable.
    /// The parent must be an authenticated head already known to this queue;
    /// the branch is never inserted into the canonical pending sequence.
    pub fn retain_losing_fork(
        &mut self,
        intent: NativeFinalizationIntentV0,
        reference_digest: Hash32V0,
    ) -> NativeBoundaryResultV0<()> {
        self.validate_v0()?;
        if self.contains_exact_intent_v0(&intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::Duplicate,
                "finalization_fork.identity",
            ));
        }
        if self.contains_conflicting_identity_v0(&intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_fork.identity",
            ));
        }
        if !self.known_head_v0(intent.parent()) {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "finalization_fork.parent",
            ));
        }
        if self.forks.len() >= MAX_FINALIZATION_QUEUE_ENTRIES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "finalization_fork.retained",
            ));
        }
        let mut next = self.clone();
        next.forks
            .push(NativeFinalizationForkV0::new(intent, reference_digest)?);
        next.validate_v0()?;
        *self = next;
        Ok(())
    }

    /// Atomically acknowledges the queue front with an exact post-commit
    /// readback.  A clone-and-validate commit gives this in-memory contract the
    /// same no-partial-mutation property required from a SQLite adapter.
    pub fn acknowledge_front(
        &mut self,
        readback: NativeFinalizationApplyReadbackV0,
    ) -> NativeBoundaryResultV0<NativeFinalizationApplyOutcomeV0> {
        self.validate_v0()?;
        let intent = readback.intent();
        if let Some(existing) = self.history.iter().find(|entry| entry.intent() == intent) {
            if existing == &readback {
                return Ok(NativeFinalizationApplyOutcomeV0::ExactReplay(
                    existing.clone(),
                ));
            }
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_queue.replay",
            ));
        }
        if self
            .history
            .iter()
            .any(|entry| entry.intent().target().block_id() == intent.target().block_id())
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_queue.target_collision",
            ));
        }
        let Some(front) = self.pending.first() else {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "finalization_queue.empty",
            ));
        };
        if front != intent {
            return Err(error(
                NativeBoundaryErrorCodeV0::NonContiguous,
                "finalization_queue.front",
            ));
        }
        if intent.parent() != &self.committed_head {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_queue.committed_head",
            ));
        }

        let mut next = self.clone();
        next.pending.remove(0);
        next.committed_head = intent.target().clone();
        next.history.push(readback.clone());
        next.validate_v0()?;
        *self = next;
        Ok(NativeFinalizationApplyOutcomeV0::NewlyCommitted(readback))
    }

    /// Classifies a response-loss retry from the queue's exact retained
    /// history.  No caller-supplied “already applied” boolean is accepted.
    pub fn reconcile(
        &self,
        intent: &NativeFinalizationIntentV0,
    ) -> NativeBoundaryResultV0<NativeFinalizationRetryDispositionV0> {
        self.validate_v0()?;
        if let Some(readback) = self.history.iter().find(|entry| entry.intent() == intent) {
            return Ok(NativeFinalizationRetryDispositionV0::ExactCommitted(
                readback.clone(),
            ));
        }
        if self.pending.contains(intent) {
            return Ok(NativeFinalizationRetryDispositionV0::Pending);
        }
        if self.forks.iter().any(|entry| entry.intent() == intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::Duplicate,
                "finalization_queue.reconcile_losing_fork",
            ));
        }
        if self.contains_conflicting_identity_v0(intent) {
            return Err(error(
                NativeBoundaryErrorCodeV0::BindingMismatch,
                "finalization_queue.reconcile_collision",
            ));
        }
        Err(error(
            NativeBoundaryErrorCodeV0::InvalidTransition,
            "finalization_queue.reconcile",
        ))
    }

    /// Reclaims only fork records whose explicit reference is absent and which
    /// are not named as a parent by another retained/canonical pending record.
    /// An empty reference list is allowed for a fully audited owner; an
    /// unauthenticated caller must not invoke this method.
    pub fn reclaim_unreferenced_forks(
        &mut self,
        live_reference_digests: &[Hash32V0],
    ) -> NativeBoundaryResultV0<usize> {
        self.validate_v0()?;
        let pending_or_fork_child = |fork: &NativeFinalizationForkV0,
                                     pending: &[NativeFinalizationIntentV0],
                                     forks: &[NativeFinalizationForkV0]| {
            pending
                .iter()
                .any(|entry| entry.parent() == fork.intent().target())
                || forks.iter().any(|other| {
                    other.intent() != fork.intent()
                        && other.intent().parent() == fork.intent().target()
                })
        };
        let pending = self.pending.clone();
        let forks = self.forks.clone();
        let mut removed = 0usize;
        let mut next = self.clone();
        next.forks.retain(|fork| {
            let referenced = live_reference_digests.contains(&fork.reference_digest());
            let protected_by_child = pending_or_fork_child(fork, &pending, &forks);
            if !referenced && !protected_by_child {
                removed = removed.saturating_add(1);
                false
            } else {
                true
            }
        });
        next.validate_v0()?;
        *self = next;
        Ok(removed)
    }

    /// Audits all local queue invariants.  This is intentionally public so a
    /// durable adapter can run it after a fresh reopen before exposing any
    /// retry disposition.
    pub fn validate_v0(&self) -> NativeBoundaryResultV0<()> {
        if self.capacity == 0 || self.capacity > MAX_FINALIZATION_QUEUE_ENTRIES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::InvalidTransition,
                "finalization_queue.capacity",
            ));
        }
        if self.pending.len() > self.capacity
            || self.history.len() > MAX_FINALIZATION_QUEUE_ENTRIES_V0
            || self.forks.len() > MAX_FINALIZATION_QUEUE_ENTRIES_V0
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "finalization_queue.length",
            ));
        }
        for pair in self.history.windows(2) {
            if pair[1].intent().parent() != pair[0].committed_head()
                || pair[1].intent().target().height()
                    != pair[0].intent().target().height().checked_next()?
                || pair[1].durable_sequence() <= pair[0].durable_sequence()
            {
                return Err(error(
                    NativeBoundaryErrorCodeV0::InvalidTransition,
                    "finalization_history.order",
                ));
            }
        }
        if let Some(last) = self.history.last() {
            if last.committed_head() != &self.committed_head {
                return Err(error(
                    NativeBoundaryErrorCodeV0::BindingMismatch,
                    "finalization_history.head",
                ));
            }
        }
        let mut expected_parent = self.committed_head.clone();
        for entry in &self.pending {
            if entry.parent() != &expected_parent {
                return Err(error(
                    NativeBoundaryErrorCodeV0::NonContiguous,
                    "finalization_queue.order",
                ));
            }
            expected_parent = entry.target().clone();
        }
        for (index, first) in self.pending.iter().enumerate() {
            for second in self.pending.iter().skip(index + 1) {
                if first == second || Self::identity_conflict_v0(first, second) {
                    return Err(error(
                        NativeBoundaryErrorCodeV0::Duplicate,
                        "finalization_queue.identity",
                    ));
                }
            }
        }
        for (index, first) in self.history.iter().enumerate() {
            for second in self.history.iter().skip(index + 1) {
                if first.intent() == second.intent()
                    || Self::identity_conflict_v0(first.intent(), second.intent())
                {
                    return Err(error(
                        NativeBoundaryErrorCodeV0::Duplicate,
                        "finalization_history.identity",
                    ));
                }
            }
        }
        for entry in &self.pending {
            if self.history.iter().any(|done| {
                done.intent() == entry || Self::identity_conflict_v0(done.intent(), entry)
            }) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::BindingMismatch,
                    "finalization_queue.history_collision",
                ));
            }
        }
        for (index, first) in self.forks.iter().enumerate() {
            if self.contains_canonical_target_v0(first.intent().target().block_id()) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::BindingMismatch,
                    "finalization_fork.canonical_target",
                ));
            }
            for second in self.forks.iter().skip(index + 1) {
                if first.intent() == second.intent()
                    || Self::identity_conflict_v0(first.intent(), second.intent())
                {
                    return Err(error(
                        NativeBoundaryErrorCodeV0::Duplicate,
                        "finalization_fork.identity",
                    ));
                }
            }
            if !self.known_head_v0(first.intent().parent()) {
                return Err(error(
                    NativeBoundaryErrorCodeV0::NonContiguous,
                    "finalization_fork.parent",
                ));
            }
        }
        Ok(())
    }

    fn contains_exact_intent_v0(&self, intent: &NativeFinalizationIntentV0) -> bool {
        self.pending.contains(intent)
            || self.history.iter().any(|entry| entry.intent() == intent)
            || self.forks.iter().any(|entry| entry.intent() == intent)
    }

    fn contains_conflicting_identity_v0(&self, intent: &NativeFinalizationIntentV0) -> bool {
        self.pending
            .iter()
            .any(|entry| Self::identity_conflict_v0(entry, intent))
            || self
                .history
                .iter()
                .any(|entry| Self::identity_conflict_v0(entry.intent(), intent))
            || self
                .forks
                .iter()
                .any(|entry| Self::identity_conflict_v0(entry.intent(), intent))
    }

    fn contains_canonical_target_v0(&self, block_id: BlockIdV0) -> bool {
        self.committed_head.block_id() == block_id
            || self
                .pending
                .iter()
                .any(|entry| entry.target().block_id() == block_id)
            || self
                .history
                .iter()
                .any(|entry| entry.intent().target().block_id() == block_id)
    }

    fn known_head_v0(&self, head: &ApplicationHeadV0) -> bool {
        &self.committed_head == head
            || self.history.iter().any(|entry| {
                entry.committed_head() == head || entry.intent().parent() == head
            })
            || self.pending.iter().any(|entry| {
                entry.target() == head || entry.parent() == head
            })
            || self
                .forks
                .iter()
                .any(|entry| entry.intent().target() == head || entry.intent().parent() == head)
    }

    fn identity_conflict_v0(
        first: &NativeFinalizationIntentV0,
        second: &NativeFinalizationIntentV0,
    ) -> bool {
        if first == second {
            return false;
        }
        // Body and JMT-plan digests may legitimately repeat for two distinct
        // blocks (for example, an empty deterministic block).  An overlay
        // checksum is expected to be target-bound by the upstream manifest,
        // so an identical overlay/body/JMT tuple on another target is retained
        // as a conservative alias/collision fence.  The queue cannot verify
        // that binding itself; source cardinality and route/profile scope
        // still belong to the accepted upstream carrier.
        first.target().block_id() == second.target().block_id()
            || first.proof_id() == second.proof_id()
            || (first.overlay_checksum() == second.overlay_checksum()
                && first.body_digest() == second.body_digest()
                && first.jmt_plan_digest() == second.jmt_plan_digest())
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
