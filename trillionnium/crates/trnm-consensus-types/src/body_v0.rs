use alloc::{boxed::Box, vec::Vec};

use crate::{
    canonical::{canonical_hash, try_canonical_bytes, Encoder, DOMAIN_DOUBLE_SIGN_EVIDENCE},
    decode_application_payload_v0_exact_for_root_binding, decode_double_vote_evidence_v0_exact,
    ordered_leaf_digest_v0, BlockHeader, BlockId, BlockKind, CommonConsensusContextV0,
    ConsensusParametersV0, EvidenceId, EvidenceRoot, Height, MessageKind, NextEpochCommitmentHash,
    OrderedRootV0, PayloadDigest, ReceiptsRoot, Result, RootKind, SignatureBytes,
    SignatureVerifier, SigningRoot, StateRoot, ValidationError, ValidatorId, ValidatorSet, Vote,
    SCHEMA_VERSION_V0,
};

pub type BlockValidationResult<T> = core::result::Result<T, BlockValidationError>;

/// Stable semantic/admission errors for the ordinary and checkpoint
/// block-commitment kernels.
/// Exact byte parsing uses the separate `DecodeErrorCode` taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BlockValidationErrorCode {
    ReceiptCountMismatch = 0,
    ReceiptIndexMismatch = 1,
    PayloadLeafMismatch = 2,
    NonCanonicalEvidenceOrder = 3,
    DuplicateEvidence = 4,
    PayloadRootMismatch = 5,
    ReceiptsRootMismatch = 6,
    EvidenceRootMismatch = 7,
    ReceiptListSizeExceeded = 8,
    LogicalBlockSizeExceeded = 9,
    NonRegularBlock = 10,
    ParametersContextMismatch = 11,
    ValidatorSetContextMismatch = 12,
    InvalidEvidenceSignature = 13,
    NonCheckpointBlock = 14,
    StateRootMismatch = 15,
    NextEpochCommitmentMismatch = 16,
}

impl BlockValidationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptCountMismatch => "receipt_count_mismatch",
            Self::ReceiptIndexMismatch => "receipt_index_mismatch",
            Self::PayloadLeafMismatch => "payload_leaf_mismatch",
            Self::NonCanonicalEvidenceOrder => "noncanonical_evidence_order",
            Self::DuplicateEvidence => "duplicate_evidence",
            Self::PayloadRootMismatch => "payload_root_mismatch",
            Self::ReceiptsRootMismatch => "receipts_root_mismatch",
            Self::EvidenceRootMismatch => "evidence_root_mismatch",
            Self::ReceiptListSizeExceeded => "receipt_list_size_exceeded",
            Self::LogicalBlockSizeExceeded => "logical_block_size_exceeded",
            Self::NonRegularBlock => "non_regular_block",
            Self::ParametersContextMismatch => "parameters_context_mismatch",
            Self::ValidatorSetContextMismatch => "validator_set_context_mismatch",
            Self::InvalidEvidenceSignature => "invalid_evidence_signature",
            Self::NonCheckpointBlock => "non_checkpoint_block",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::NextEpochCommitmentMismatch => "next_epoch_commitment_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockValidationError {
    code: BlockValidationErrorCode,
}

impl BlockValidationError {
    pub const fn new(code: BlockValidationErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> BlockValidationErrorCode {
        self.code
    }
}

impl core::fmt::Display for BlockValidationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

/// The exact CEV0 `List<Bytes>` of application transactions in execution
/// order. Transaction bytes are opaque to consensus and are never
/// decode/re-encoded before the payload root is computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationPayloadV0 {
    transactions: Vec<Vec<u8>>,
    cev0_len: u32,
}

impl ApplicationPayloadV0 {
    pub fn new(transactions: Vec<Vec<u8>>) -> Result<Self> {
        checked_u32_len("ApplicationPayloadV0 transactions", transactions.len())?;
        let mut cev0_len = 4u64;
        for transaction in &transactions {
            checked_u32_len("ApplicationPayloadV0 transaction bytes", transaction.len())?;
            cev0_len = checked_framed_sum(
                cev0_len,
                transaction.len(),
                "ApplicationPayloadV0 CEV0 length",
            )?;
        }
        let cev0_len = u32::try_from(cev0_len).map_err(|_| ValidationError::LengthOverflow {
            field: "ApplicationPayloadV0 CEV0 bytes",
            actual: usize_from_u64_saturating(cev0_len),
            maximum: u32::MAX as usize,
        })?;
        Ok(Self {
            transactions,
            cev0_len,
        })
    }

    pub fn transactions(&self) -> &[Vec<u8>] {
        &self.transactions
    }

    pub fn transaction(&self, index: u32) -> Option<&[u8]> {
        self.transactions.get(index as usize).map(Vec::as_slice)
    }

    pub const fn transaction_count(&self) -> u32 {
        self.transactions.len() as u32
    }

    pub const fn cev0_len(&self) -> u32 {
        self.cev0_len
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            encoder.list_len(self.transactions.len());
            for transaction in &self.transactions {
                encoder.bytes(transaction);
            }
        })
    }

    pub fn payload_root(&self) -> Result<PayloadDigest> {
        Ok(PayloadDigest::new(
            OrderedRootV0::from_items(RootKind::Payload, &self.transactions)?.digest(),
        ))
    }
}

/// One raw-key-ordered event attribute. Key and value bytes are exact UTF-8
/// runtime strings; no normalization is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEventAttributeV0 {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ExecutionEventAttributeV0 {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self> {
        validate_runtime_string("ExecutionEventV0 attribute key", &key)?;
        validate_runtime_string("ExecutionEventV0 attribute value", &value)?;
        Ok(Self { key, value })
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.bytes(&self.key);
        encoder.bytes(&self.value);
    }

    fn encoded_len(&self) -> Result<u64> {
        let length =
            checked_framed_sum(0, self.key.len(), "ExecutionEventAttributeV0 CEV0 length")?;
        checked_framed_sum(
            length,
            self.value.len(),
            "ExecutionEventAttributeV0 CEV0 length",
        )
    }
}

/// Frozen execution-event commitment value. Attribute order is semantic:
/// keys must be strictly increasing by their unmodified raw UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEventV0 {
    kind: Vec<u8>,
    attributes: Vec<ExecutionEventAttributeV0>,
}

impl ExecutionEventV0 {
    pub fn new(kind: Vec<u8>, attributes: Vec<ExecutionEventAttributeV0>) -> Result<Self> {
        validate_runtime_string("ExecutionEventV0 kind", &kind)?;
        checked_u32_len("ExecutionEventV0 attributes", attributes.len())?;
        for pair in attributes.windows(2) {
            if pair[0].key() >= pair[1].key() {
                return Err(ValidationError::InvalidBlock(
                    "execution-event attributes are not strictly ordered by raw key bytes",
                ));
            }
        }
        Ok(Self { kind, attributes })
    }

    pub fn kind(&self) -> &[u8] {
        &self.kind
    }

    pub fn attributes(&self) -> &[ExecutionEventAttributeV0] {
        &self.attributes
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.bytes(&self.kind);
        encoder.list_len(self.attributes.len());
        for attribute in &self.attributes {
            attribute.encode_cev0(encoder);
        }
    }

    fn encoded_len(&self) -> Result<u64> {
        let mut length = checked_framed_sum(0, self.kind.len(), "ExecutionEventV0 CEV0 length")?
            .checked_add(4)
            .ok_or(ValidationError::ArithmeticOverflow(
                "ExecutionEventV0 CEV0 length",
            ))?;
        for attribute in &self.attributes {
            length = length.checked_add(attribute.encoded_len()?).ok_or(
                ValidationError::ArithmeticOverflow("ExecutionEventV0 CEV0 length"),
            )?;
        }
        Ok(length)
    }
}

/// Exact deterministic receipt commitment. This value intentionally has no
/// execution outcome/status field: runtime execution policy remains outside
/// this semantic commitment kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceiptCommitmentV0 {
    transaction_index: u32,
    payload_leaf_hash: [u8; 32],
    gas_used: u64,
    fee_charged: u128,
    events: Vec<ExecutionEventV0>,
    cev0_len: u32,
}

impl ExecutionReceiptCommitmentV0 {
    pub fn new(
        transaction_index: u32,
        payload_leaf_hash: [u8; 32],
        gas_used: u64,
        fee_charged: u128,
        events: Vec<ExecutionEventV0>,
    ) -> Result<Self> {
        checked_u32_len("ExecutionReceiptCommitmentV0 events", events.len())?;
        let mut cev0_len = 2u64 + 4 + 32 + 8 + 16 + 4;
        for event in &events {
            cev0_len = cev0_len.checked_add(event.encoded_len()?).ok_or(
                ValidationError::ArithmeticOverflow("ExecutionReceiptCommitmentV0 CEV0 length"),
            )?;
        }
        let cev0_len = u32::try_from(cev0_len).map_err(|_| ValidationError::LengthOverflow {
            field: "ExecutionReceiptCommitmentV0 CEV0 bytes",
            actual: usize_from_u64_saturating(cev0_len),
            maximum: u32::MAX as usize,
        })?;
        Ok(Self {
            transaction_index,
            payload_leaf_hash,
            gas_used,
            fee_charged,
            events,
            cev0_len,
        })
    }

    pub fn for_transaction(
        payload: &ApplicationPayloadV0,
        transaction_index: u32,
        gas_used: u64,
        fee_charged: u128,
        events: Vec<ExecutionEventV0>,
    ) -> Result<Self> {
        let transaction =
            payload
                .transaction(transaction_index)
                .ok_or(ValidationError::InvalidBlock(
                    "receipt transaction index is outside the payload",
                ))?;
        Self::new(
            transaction_index,
            ordered_leaf_digest_v0(RootKind::Payload, transaction_index, transaction)?,
            gas_used,
            fee_charged,
            events,
        )
    }

    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    pub const fn payload_leaf_hash(&self) -> &[u8; 32] {
        &self.payload_leaf_hash
    }

    pub const fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub const fn fee_charged(&self) -> u128 {
        self.fee_charged
    }

    pub fn events(&self) -> &[ExecutionEventV0] {
        &self.events
    }

    pub const fn cev0_len(&self) -> u32 {
        self.cev0_len
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        encoder.u32(self.transaction_index);
        encoder.fixed(&self.payload_leaf_hash);
        encoder.u64(self.gas_used);
        encoder.u128(self.fee_charged);
        encoder.list_len(self.events.len());
        for event in &self.events {
            event.encode_cev0(encoder);
        }
    }
}

/// Caller-supplied receipt commitments validated one-for-one against a
/// canonical application payload.
///
/// Protocol integration must supply these values from the locally authorized
/// deterministic runtime. This type proves only their shape and payload
/// relations; construction does not establish execution or runtime
/// provenance and is not a peer receipt-admission path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceiptsV0 {
    receipts: Vec<ExecutionReceiptCommitmentV0>,
}

impl ExecutionReceiptsV0 {
    pub fn new(
        payload: &ApplicationPayloadV0,
        receipts: Vec<ExecutionReceiptCommitmentV0>,
    ) -> Result<Self> {
        Self::new_admission(payload, receipts).map_err(block_validation_as_validation_error)
    }

    pub fn new_admission(
        payload: &ApplicationPayloadV0,
        receipts: Vec<ExecutionReceiptCommitmentV0>,
    ) -> BlockValidationResult<Self> {
        u32::try_from(receipts.len()).map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ReceiptCountMismatch)
        })?;
        let value = Self { receipts };
        value.validate_for_payload_admission(payload)?;
        Ok(value)
    }

    pub fn receipts(&self) -> &[ExecutionReceiptCommitmentV0] {
        &self.receipts
    }

    pub fn validate_for_payload(&self, payload: &ApplicationPayloadV0) -> Result<()> {
        self.validate_for_payload_admission(payload)
            .map_err(block_validation_as_validation_error)
    }

    pub fn validate_for_payload_admission(
        &self,
        payload: &ApplicationPayloadV0,
    ) -> BlockValidationResult<()> {
        if self.receipts.len() != payload.transactions.len() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ReceiptCountMismatch,
            ));
        }
        for (index, (receipt, transaction)) in
            self.receipts.iter().zip(&payload.transactions).enumerate()
        {
            let index = u32::try_from(index).map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::ReceiptIndexMismatch)
            })?;
            if receipt.transaction_index != index {
                return Err(BlockValidationError::new(
                    BlockValidationErrorCode::ReceiptIndexMismatch,
                ));
            }
            let expected =
                ordered_leaf_digest_v0(RootKind::Payload, index, transaction).map_err(|_| {
                    BlockValidationError::new(BlockValidationErrorCode::PayloadLeafMismatch)
                })?;
            if receipt.payload_leaf_hash != expected {
                return Err(BlockValidationError::new(
                    BlockValidationErrorCode::PayloadLeafMismatch,
                ));
            }
        }
        Ok(())
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        let receipt_bytes = self.receipt_bytes()?;
        try_canonical_bytes(|encoder| {
            encoder.list_len(receipt_bytes.len());
            for receipt in &receipt_bytes {
                encoder.bytes(receipt);
            }
        })
    }

    pub fn cev0_len(&self) -> Result<u64> {
        let mut length = 4u64;
        for receipt in &self.receipts {
            length = checked_framed_sum(
                length,
                receipt.try_cev0_bytes()?.len(),
                "ExecutionReceiptsV0 CEV0 length",
            )?;
        }
        Ok(length)
    }

    pub fn receipts_root(&self) -> Result<ReceiptsRoot> {
        let receipt_bytes = self.receipt_bytes()?;
        Ok(ReceiptsRoot::new(
            OrderedRootV0::from_items(RootKind::Receipts, &receipt_bytes)?.digest(),
        ))
    }

    pub fn validate_max_bytes(&self, maximum: u32) -> Result<()> {
        self.validate_max_bytes_admission(maximum)
            .map_err(block_validation_as_validation_error)
    }

    pub fn validate_max_bytes_admission(&self, maximum: u32) -> BlockValidationResult<()> {
        let cev0_len = self.cev0_len().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ReceiptListSizeExceeded)
        })?;
        if cev0_len > u64::from(maximum) {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ReceiptListSizeExceeded,
            ));
        }
        Ok(())
    }

    fn receipt_bytes(&self) -> Result<Vec<Vec<u8>>> {
        self.receipts
            .iter()
            .map(ExecutionReceiptCommitmentV0::try_cev0_bytes)
            .collect()
    }
}

/// Exact signed vote record embedded in `DoubleVoteEvidenceV0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteEvidenceRecordV0 {
    context: CommonConsensusContextV0,
    height: Height,
    block_id: BlockId,
    author: ValidatorId,
    signature: SignatureBytes,
}

impl VoteEvidenceRecordV0 {
    pub fn new(
        context: CommonConsensusContextV0,
        height: Height,
        block_id: BlockId,
        author: ValidatorId,
        signature: SignatureBytes,
    ) -> Result<Self> {
        context.require_kind(MessageKind::Vote)?;
        signature.validate_shape()?;
        Ok(Self {
            context,
            height,
            block_id,
            author,
            signature,
        })
    }

    pub const fn context(&self) -> &CommonConsensusContextV0 {
        &self.context
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    pub fn signing_root(&self) -> SigningRoot {
        Vote::signing_root_for(self.context, self.height, self.block_id)
            .expect("VoteEvidenceRecordV0 stores a validated vote context")
    }

    pub fn validate_against_validator_set(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.context.require_kind(MessageKind::Vote)?;
        if self.context.genesis_hash() != validator_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.context.chain_id() != validator_set.chain_id() {
            return Err(ValidationError::ChainIdMismatch);
        }
        if self.context.protocol_version() != validator_set.protocol_version() {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        if self.context.epoch() != validator_set.epoch() {
            return Err(ValidationError::EpochMismatch);
        }
        if self.context.validator_set_hash() != validator_set.id() {
            return Err(ValidationError::ValidatorSetIdMismatch);
        }
        if validator_set.validator(self.author).is_none() {
            return Err(ValidationError::UnknownValidator(Box::new(self.author)));
        }
        self.signature.validate_shape()
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_against_validator_set(validator_set)?;
        let validator = validator_set
            .validator(self.author)
            .ok_or_else(|| ValidationError::UnknownValidator(Box::new(self.author)))?;
        if !verifier.verify(validator, &self.signing_root(), &self.signature) {
            return Err(ValidationError::InvalidSignature(Box::new(self.author)));
        }
        Ok(())
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        self.context.encode(encoder);
        encoder.u64(self.height.get());
        encoder.fixed(self.block_id.as_bytes());
        encoder.bytes(self.author.as_bytes());
        encoder.fixed(self.signature.as_bytes());
    }
}

impl From<&Vote> for VoteEvidenceRecordV0 {
    fn from(vote: &Vote) -> Self {
        Self {
            context: *vote.context(),
            height: vote.height(),
            block_id: vote.block_id(),
            author: vote.author(),
            signature: *vote.signature(),
        }
    }
}

/// Canonical objective v0 evidence. Construction normalizes arrival order by
/// reconstructed vote signing root; exact decoders can use
/// [`Self::from_ordered_records`] to reject a non-canonical wire preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleVoteEvidenceV0 {
    first: VoteEvidenceRecordV0,
    second: VoteEvidenceRecordV0,
}

impl DoubleVoteEvidenceV0 {
    pub fn new(mut first: VoteEvidenceRecordV0, mut second: VoteEvidenceRecordV0) -> Result<Self> {
        if first.signing_root() > second.signing_root() {
            core::mem::swap(&mut first, &mut second);
        }
        Self::from_ordered_records(first, second)
    }

    pub fn from_ordered_records(
        first: VoteEvidenceRecordV0,
        second: VoteEvidenceRecordV0,
    ) -> Result<Self> {
        let value = Self { first, second };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn first(&self) -> &VoteEvidenceRecordV0 {
        &self.first
    }

    pub const fn second(&self) -> &VoteEvidenceRecordV0 {
        &self.second
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.first.context.require_kind(MessageKind::Vote)?;
        self.second.context.require_kind(MessageKind::Vote)?;
        self.first.signature.validate_shape()?;
        self.second.signature.validate_shape()?;
        if self.first.context != self.second.context {
            return Err(ValidationError::InvalidEvidence(
                "double-vote records do not have byte-identical contexts",
            ));
        }
        if self.first.author != self.second.author {
            return Err(ValidationError::InvalidEvidence(
                "double-vote records do not have the same author",
            ));
        }
        if self.first.height == self.second.height && self.first.block_id == self.second.block_id {
            return Err(ValidationError::InvalidEvidence(
                "double-vote records do not contain different vote tuples",
            ));
        }
        if self.first.signing_root() >= self.second.signing_root() {
            return Err(ValidationError::InvalidEvidence(
                "double-vote records are not in strict signing-root order",
            ));
        }
        Ok(())
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_shape()?;
        self.first.verify(validator_set, verifier)?;
        self.second.verify(validator_set, verifier)
    }

    pub fn evidence_id(&self) -> EvidenceId {
        EvidenceId::new(canonical_hash(DOMAIN_DOUBLE_SIGN_EVIDENCE, |encoder| {
            self.encode_cev0(encoder);
        }))
    }

    pub fn id(&self) -> EvidenceId {
        self.evidence_id()
    }

    pub fn from_votes(first: &Vote, second: &Vote) -> Result<Self> {
        Self::new(first.into(), second.into())
    }

    pub fn try_cev0_bytes(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_cev0(encoder))
    }

    fn encode_cev0(&self, encoder: &mut Encoder) {
        encoder.u16(SCHEMA_VERSION_V0);
        self.first.encode_cev0(encoder);
        self.second.encode_cev0(encoder);
    }
}

/// Canonical logical body fields for a block. Receipts are deliberately not
/// stored here: they are deterministically derived from execution and supplied
/// separately when their commitment is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBodyV0 {
    application_payload: ApplicationPayloadV0,
    evidence: Vec<DoubleVoteEvidenceV0>,
}

/// Proof that the ordinary (non-epoch) canonical body, caller-supplied receipt
/// commitment relations, active validator-set binding, caller-supplied
/// evidence-verifier acceptance, and committed byte limits passed this
/// semantic kernel.
///
/// This token does **not** prove that receipts came from an authorized runtime,
/// attest which [`SignatureVerifier`] implementation was supplied,
/// authenticate parent state, execute the runtime, or authorize a vote, epoch
/// transition, checkpoint, seal, or anchor. Production integration must pass
/// `trnm_consensus_crypto::StrictEd25519Verifier`; the types crate cannot name
/// or enforce that downstream implementation. Its fields are private so it
/// cannot be forged from peer-supplied bytes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedBlockCommitmentsV0 {
    block_id: BlockId,
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
}

/// Inert proof that one transport [`crate::Block`] carries an exact canonical
/// regular body whose payload/evidence roots and logical size match its
/// authenticated header.
///
/// This deliberately does not validate receipts, state execution, parent
/// provenance, evidence signatures, or application authority. It exists for
/// state-sync body transport: a finality proof authenticates headers and
/// proposal witnesses, but does not carry the complete application body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootBoundRegularBodyV0 {
    block_id: BlockId,
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
}

impl RootBoundRegularBodyV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn logical_block_size(&self) -> u64 {
        self.logical_block_size
    }

    pub const fn transaction_count(&self) -> u32 {
        self.transaction_count
    }

    pub const fn evidence_count(&self) -> u32 {
        self.evidence_count
    }
}

/// Binds the complete body bytes of one regular transport block to the roots
/// already authenticated by its header.
///
/// The result is comparison material only. In particular it cannot authorize
/// a Valid application result because receipts and the post-state root remain
/// runtime-owned.
pub fn validate_root_bound_regular_body_v0(
    block: &crate::Block,
    active_validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> BlockValidationResult<RootBoundRegularBodyV0> {
    let header = block.header();
    header.validate_shape().map_err(|_| {
        BlockValidationError::new(BlockValidationErrorCode::ParametersContextMismatch)
    })?;
    if header.block_kind() != BlockKind::Regular {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::NonRegularBlock,
        ));
    }
    parameters.validate_safety_invariants().map_err(|_| {
        BlockValidationError::new(BlockValidationErrorCode::ParametersContextMismatch)
    })?;
    active_validator_set
        .validate_against_parameters(parameters)
        .map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ValidatorSetContextMismatch)
        })?;
    if header.consensus_parameters_hash() != parameters.hash() {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::ParametersContextMismatch,
        ));
    }
    if header.genesis_hash() != active_validator_set.genesis_hash()
        || header.chain_id() != active_validator_set.chain_id()
        || header.protocol_version() != active_validator_set.protocol_version()
        || header.epoch() != active_validator_set.epoch()
        || header.validator_set_id() != active_validator_set.id()
    {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::ValidatorSetContextMismatch,
        ));
    }
    let payload = decode_application_payload_v0_exact_for_root_binding(
        block.application_payload(),
        parameters,
    )
    .map_err(|_| BlockValidationError::new(BlockValidationErrorCode::PayloadRootMismatch))?;
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(block.evidence_objects().len())
        .map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
        })?;
    for encoded in block.evidence_objects() {
        evidence.push(
            decode_double_vote_evidence_v0_exact(encoded, active_validator_set).map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::NonCanonicalEvidenceOrder)
            })?,
        );
    }
    let body = BlockBodyV0::new_admission(payload, evidence)?;
    if body
        .payload_root()
        .map_err(|_| BlockValidationError::new(BlockValidationErrorCode::PayloadRootMismatch))?
        != header.payload_root()
    {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::PayloadRootMismatch,
        ));
    }
    if body
        .evidence_root()
        .map_err(|_| BlockValidationError::new(BlockValidationErrorCode::EvidenceRootMismatch))?
        != header.evidence_root()
    {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::EvidenceRootMismatch,
        ));
    }
    let logical_block_size = body.logical_block_size_v0(header).map_err(|_| {
        BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
    })?;
    if usize::try_from(logical_block_size).ok() != Some(block.logical_block_size())
        || logical_block_size > u64::from(parameters.max_block_bytes())
    {
        return Err(BlockValidationError::new(
            BlockValidationErrorCode::LogicalBlockSizeExceeded,
        ));
    }
    Ok(RootBoundRegularBodyV0 {
        block_id: block.id(),
        logical_block_size,
        transaction_count: body.application_payload().transaction_count(),
        evidence_count: u32::try_from(body.evidence().len()).map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
        })?,
    })
}

/// Proof that the canonical checkpoint body, locally derived receipts, all
/// four header roots, the expected next-epoch commitment, and committed byte
/// limits passed this static semantic kernel.
///
/// The expected state root and receipt commitments remain caller-supplied
/// local execution results. This token therefore does **not** prove runtime or
/// parent-state provenance, derive the next-epoch commitment, authenticate the
/// active validator set, verify evidence signatures, prove checkpoint
/// geometry/finality, or authorize a proposal, vote, seal, or handoff. Its
/// fields are private so peer bytes cannot directly forge it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedCheckpointCommitmentsV0 {
    block_id: BlockId,
    payload_root: PayloadDigest,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    next_epoch_commitment_hash: NextEpochCommitmentHash,
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
}

impl ValidatedCheckpointCommitmentsV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn payload_root(&self) -> PayloadDigest {
        self.payload_root
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn receipts_root(&self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub const fn evidence_root(&self) -> EvidenceRoot {
        self.evidence_root
    }

    pub const fn next_epoch_commitment_hash(&self) -> NextEpochCommitmentHash {
        self.next_epoch_commitment_hash
    }

    pub const fn logical_block_size(&self) -> u64 {
        self.logical_block_size
    }

    pub const fn transaction_count(&self) -> u32 {
        self.transaction_count
    }

    pub const fn evidence_count(&self) -> u32 {
        self.evidence_count
    }
}

impl ValidatedBlockCommitmentsV0 {
    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn logical_block_size(&self) -> u64 {
        self.logical_block_size
    }

    pub const fn transaction_count(&self) -> u32 {
        self.transaction_count
    }

    pub const fn evidence_count(&self) -> u32 {
        self.evidence_count
    }
}

impl BlockBodyV0 {
    pub fn new(
        application_payload: ApplicationPayloadV0,
        evidence: Vec<DoubleVoteEvidenceV0>,
    ) -> Result<Self> {
        Self::new_admission(application_payload, evidence)
            .map_err(block_validation_as_validation_error)
    }

    pub fn new_admission(
        application_payload: ApplicationPayloadV0,
        evidence: Vec<DoubleVoteEvidenceV0>,
    ) -> BlockValidationResult<Self> {
        u32::try_from(evidence.len()).map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
        })?;
        for item in &evidence {
            item.validate_shape().map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::NonCanonicalEvidenceOrder)
            })?;
            let item_len = item.try_cev0_bytes().map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
            })?;
            u32::try_from(item_len.len()).map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
            })?;
        }
        validate_evidence_order(&evidence)?;
        Ok(Self {
            application_payload,
            evidence,
        })
    }

    pub const fn application_payload(&self) -> &ApplicationPayloadV0 {
        &self.application_payload
    }

    pub fn evidence(&self) -> &[DoubleVoteEvidenceV0] {
        &self.evidence
    }

    pub fn payload_root(&self) -> Result<PayloadDigest> {
        self.application_payload.payload_root()
    }

    pub fn evidence_root(&self) -> Result<EvidenceRoot> {
        let evidence_bytes = self.evidence_bytes()?;
        Ok(EvidenceRoot::new(
            OrderedRootV0::from_items(RootKind::Evidence, &evidence_bytes)?.digest(),
        ))
    }

    pub fn verify_evidence<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        for evidence in &self.evidence {
            evidence.verify(validator_set, verifier)?;
        }
        Ok(())
    }

    pub fn logical_block_size_v0(&self, header: &BlockHeader) -> Result<u64> {
        let header_len = u64::try_from(header.try_cev0_bytes()?.len()).map_err(|_| {
            ValidationError::ArithmeticOverflow("BlockHeaderV0 CEV0 length conversion")
        })?;
        let mut size = header_len
            .checked_add(4)
            .and_then(|value| value.checked_add(u64::from(self.application_payload.cev0_len())))
            .and_then(|value| value.checked_add(4))
            .ok_or(ValidationError::ArithmeticOverflow(
                "logical_block_size_v0 fixed fields",
            ))?;
        for item in &self.evidence {
            let item_len = u64::try_from(item.try_cev0_bytes()?.len()).map_err(|_| {
                ValidationError::ArithmeticOverflow("evidence CEV0 length conversion")
            })?;
            size = size
                .checked_add(4)
                .and_then(|value| value.checked_add(item_len))
                .ok_or(ValidationError::ArithmeticOverflow(
                    "logical_block_size_v0 evidence",
                ))?;
        }
        Ok(size)
    }

    pub fn validate_max_block_bytes(&self, header: &BlockHeader, maximum: u32) -> Result<()> {
        self.validate_max_block_bytes_admission(header, maximum)
            .map_err(block_validation_as_validation_error)
    }

    pub fn validate_max_block_bytes_admission(
        &self,
        header: &BlockHeader,
        maximum: u32,
    ) -> BlockValidationResult<()> {
        let size = self.logical_block_size_v0(header).map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
        })?;
        if size > u64::from(maximum) {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::LogicalBlockSizeExceeded,
            ));
        }
        Ok(())
    }

    /// Validates only frozen body/receipt roots and exact size limits.
    ///
    /// This partial helper does not bind the active validator set or verify
    /// objective-evidence signatures, in addition to not executing
    /// transactions or authenticating parent state. Its `Ok(())` is therefore
    /// not ordinary block admission and must not authorize a vote, epoch,
    /// anchor, or transition. Use [`Self::validate_ordinary_commitments`] for
    /// the complete static ordinary commitment capability.
    pub fn validate_static_root_commitments(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        self.validate_static_root_commitments_admission(header, receipts, parameters)
            .map_err(block_validation_as_validation_error)
    }

    /// Machine-readable form of [`Self::validate_static_root_commitments`].
    /// It remains a partial root/size helper, not ordinary block admission.
    pub fn validate_static_root_commitments_admission(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
    ) -> BlockValidationResult<()> {
        header.validate_shape().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ParametersContextMismatch)
        })?;
        if header.block_kind() != BlockKind::Regular {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::NonRegularBlock,
            ));
        }
        self.validate_common_static_root_commitments_admission(header, receipts, parameters)
    }

    /// Validates the exact checkpoint body/root boundary without weakening the
    /// ordinary-only validator.
    ///
    /// Protocol v0 permits a checkpoint to contain zero or more ordinary
    /// application transactions and objective evidence objects. Consequently
    /// this helper imposes no synthetic non-empty rule; it instead requires
    /// exactly one locally derived receipt per transaction and recomputes the
    /// payload, receipts, and evidence roots. `expected_state_root` must be the
    /// result of the locally authorized deterministic execution, and
    /// `expected_next_epoch_commitment_hash` must be derived by the separate
    /// authenticated epoch-commitment path.
    pub fn validate_checkpoint_static_commitments(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
        expected_state_root: StateRoot,
        expected_next_epoch_commitment_hash: NextEpochCommitmentHash,
    ) -> Result<ValidatedCheckpointCommitmentsV0> {
        self.validate_checkpoint_static_commitments_admission(
            header,
            receipts,
            parameters,
            expected_state_root,
            expected_next_epoch_commitment_hash,
        )
        .map_err(block_validation_as_validation_error)
    }

    /// Machine-readable form of
    /// [`Self::validate_checkpoint_static_commitments`].
    pub fn validate_checkpoint_static_commitments_admission(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
        expected_state_root: StateRoot,
        expected_next_epoch_commitment_hash: NextEpochCommitmentHash,
    ) -> BlockValidationResult<ValidatedCheckpointCommitmentsV0> {
        header.validate_shape().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ParametersContextMismatch)
        })?;
        if header.block_kind() != BlockKind::EpochCheckpoint {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::NonCheckpointBlock,
            ));
        }
        if header.state_root() != expected_state_root {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::StateRootMismatch,
            ));
        }
        if header.next_epoch_commitment_hash() != Some(expected_next_epoch_commitment_hash) {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::NextEpochCommitmentMismatch,
            ));
        }
        self.validate_common_static_root_commitments_admission(header, receipts, parameters)?;
        Ok(ValidatedCheckpointCommitmentsV0 {
            block_id: header.id(),
            payload_root: header.payload_root(),
            state_root: header.state_root(),
            receipts_root: header.receipts_root(),
            evidence_root: header.evidence_root(),
            next_epoch_commitment_hash: expected_next_epoch_commitment_hash,
            logical_block_size: self.logical_block_size_v0(header).map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
            })?,
            transaction_count: self.application_payload.transaction_count(),
            evidence_count: self.evidence.len() as u32,
        })
    }

    fn validate_common_static_root_commitments_admission(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
    ) -> BlockValidationResult<()> {
        parameters.validate_safety_invariants().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ParametersContextMismatch)
        })?;
        if header.consensus_parameters_hash() != parameters.hash() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ParametersContextMismatch,
            ));
        }
        validate_evidence_order(&self.evidence)?;
        let payload_root = self.payload_root().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::PayloadRootMismatch)
        })?;
        if header.payload_root() != payload_root {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::PayloadRootMismatch,
            ));
        }
        let evidence_root = self.evidence_root().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::EvidenceRootMismatch)
        })?;
        if header.evidence_root() != evidence_root {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::EvidenceRootMismatch,
            ));
        }
        receipts.validate_for_payload_admission(&self.application_payload)?;
        let receipts_root = receipts.receipts_root().map_err(|_| {
            BlockValidationError::new(BlockValidationErrorCode::ReceiptsRootMismatch)
        })?;
        if header.receipts_root() != receipts_root {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ReceiptsRootMismatch,
            ));
        }
        receipts.validate_max_bytes_admission(parameters.max_block_bytes())?;
        self.validate_max_block_bytes_admission(header, parameters.max_block_bytes())
    }

    /// Runs the complete ordinary commitment kernel, including active-set
    /// binding and evidence checks through the caller-supplied verifier.
    ///
    /// The result records verifier acceptance, not verifier identity.
    /// Production integration must supply
    /// `trnm_consensus_crypto::StrictEd25519Verifier`; test or alternate trait
    /// implementations do not make this token intrinsically strict-Ed25519.
    pub fn validate_ordinary_commitments<V: SignatureVerifier>(
        &self,
        header: &BlockHeader,
        receipts: &ExecutionReceiptsV0,
        parameters: &ConsensusParametersV0,
        active_validator_set: &ValidatorSet,
        verifier: &V,
    ) -> BlockValidationResult<ValidatedBlockCommitmentsV0> {
        self.validate_static_root_commitments_admission(header, receipts, parameters)?;
        active_validator_set
            .validate_against_parameters(parameters)
            .map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::ValidatorSetContextMismatch)
            })?;
        if header.genesis_hash() != active_validator_set.genesis_hash() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ValidatorSetContextMismatch,
            ));
        }
        if header.chain_id() != active_validator_set.chain_id() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ValidatorSetContextMismatch,
            ));
        }
        if header.protocol_version() != active_validator_set.protocol_version() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ValidatorSetContextMismatch,
            ));
        }
        if header.epoch() != active_validator_set.epoch() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ValidatorSetContextMismatch,
            ));
        }
        if header.validator_set_id() != active_validator_set.id() {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::ValidatorSetContextMismatch,
            ));
        }
        self.verify_evidence(active_validator_set, verifier)
            .map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::InvalidEvidenceSignature)
            })?;
        Ok(ValidatedBlockCommitmentsV0 {
            block_id: header.id(),
            logical_block_size: self.logical_block_size_v0(header).map_err(|_| {
                BlockValidationError::new(BlockValidationErrorCode::LogicalBlockSizeExceeded)
            })?,
            transaction_count: self.application_payload.transaction_count(),
            evidence_count: self.evidence.len() as u32,
        })
    }

    fn evidence_bytes(&self) -> Result<Vec<Vec<u8>>> {
        self.evidence
            .iter()
            .map(DoubleVoteEvidenceV0::try_cev0_bytes)
            .collect()
    }
}

fn validate_evidence_order(evidence: &[DoubleVoteEvidenceV0]) -> BlockValidationResult<()> {
    let mut previous = None;
    for item in evidence {
        let current = item.evidence_id();
        if previous == Some(current) {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::DuplicateEvidence,
            ));
        }
        if previous.is_some_and(|previous| previous > current) {
            return Err(BlockValidationError::new(
                BlockValidationErrorCode::NonCanonicalEvidenceOrder,
            ));
        }
        previous = Some(current);
    }
    Ok(())
}

fn block_validation_as_validation_error(error: BlockValidationError) -> ValidationError {
    match error.code() {
        BlockValidationErrorCode::ReceiptCountMismatch => ValidationError::InvalidBlock(
            "execution must produce exactly one receipt per transaction",
        ),
        BlockValidationErrorCode::ReceiptIndexMismatch => ValidationError::InvalidBlock(
            "receipt transaction indices are not exact and contiguous",
        ),
        BlockValidationErrorCode::PayloadLeafMismatch => ValidationError::InvalidBlock(
            "receipt payload leaf does not bind the indexed transaction",
        ),
        BlockValidationErrorCode::NonCanonicalEvidenceOrder => ValidationError::InvalidEvidence(
            "block evidence is not strictly ordered by evidence ID",
        ),
        BlockValidationErrorCode::DuplicateEvidence => {
            ValidationError::InvalidEvidence("block evidence contains a duplicate evidence ID")
        }
        BlockValidationErrorCode::PayloadRootMismatch => ValidationError::PayloadDigestMismatch,
        BlockValidationErrorCode::ReceiptsRootMismatch => {
            ValidationError::InvalidBlock("receipts root mismatch")
        }
        BlockValidationErrorCode::EvidenceRootMismatch => {
            ValidationError::InvalidBlock("evidence root mismatch")
        }
        BlockValidationErrorCode::ReceiptListSizeExceeded => {
            ValidationError::InvalidBlock("canonical receipt list exceeds max_block_bytes")
        }
        BlockValidationErrorCode::LogicalBlockSizeExceeded => {
            ValidationError::InvalidBlock("logical_block_size_v0 exceeds max_block_bytes")
        }
        BlockValidationErrorCode::NonRegularBlock => ValidationError::InvalidBlock(
            "ordinary body-validation kernel requires a regular block",
        ),
        BlockValidationErrorCode::ParametersContextMismatch => {
            ValidationError::ConsensusParametersMismatch
        }
        BlockValidationErrorCode::ValidatorSetContextMismatch => {
            ValidationError::ValidatorSetMismatch
        }
        BlockValidationErrorCode::InvalidEvidenceSignature => {
            ValidationError::InvalidEvidence("supplied evidence verifier rejected signature")
        }
        BlockValidationErrorCode::NonCheckpointBlock => ValidationError::InvalidBlock(
            "checkpoint body-validation kernel requires an epoch-checkpoint block",
        ),
        BlockValidationErrorCode::StateRootMismatch => {
            ValidationError::InvalidBlock("checkpoint state root mismatch")
        }
        BlockValidationErrorCode::NextEpochCommitmentMismatch => {
            ValidationError::InvalidBlock("checkpoint next-epoch commitment mismatch")
        }
    }
}

fn validate_runtime_string(field: &'static str, value: &[u8]) -> Result<()> {
    checked_u32_len(field, value.len())?;
    if core::str::from_utf8(value).is_err() {
        return Err(ValidationError::InvalidBlock(
            "execution-event runtime string is not valid UTF-8",
        ));
    }
    Ok(())
}

fn checked_u32_len(field: &'static str, actual: usize) -> Result<u32> {
    u32::try_from(actual).map_err(|_| ValidationError::LengthOverflow {
        field,
        actual,
        maximum: u32::MAX as usize,
    })
}

fn checked_framed_sum(total: u64, item_len: usize, field: &'static str) -> Result<u64> {
    let item_len =
        u64::try_from(item_len).map_err(|_| ValidationError::ArithmeticOverflow(field))?;
    total
        .checked_add(4)
        .and_then(|value| value.checked_add(item_len))
        .ok_or(ValidationError::ArithmeticOverflow(field))
}

fn usize_from_u64_saturating(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::{
        ChainId, ConsensusPublicKey, Epoch, GenesisHash, NextEpochCommitmentHash, ProtocolVersion,
        StateRoot, Validator, View, VotingPower,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-body-v0-test");

    /// Test-only verifier used to isolate non-cryptographic body relations.
    struct AcceptAll;

    impl SignatureVerifier for AcceptAll {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            true
        }
    }

    struct RejectAll;

    impl SignatureVerifier for RejectAll {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            false
        }
    }

    fn validator_set(parameters: &ConsensusParametersV0) -> ValidatorSet {
        let validators = (1u8..=4)
            .map(|value| {
                Validator::new(
                    ValidatorId::new([value; 32]),
                    ConsensusPublicKey::new([value + 16; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(3),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn vote(validator_set: &ValidatorSet, height: u64, block_byte: u8, signature_byte: u8) -> Vote {
        Vote::new(
            TEST_CHAIN,
            ProtocolVersion::V0,
            validator_set.epoch(),
            View::new(9),
            Height::new(height),
            BlockId::new([block_byte; 32]),
            validator_set.id(),
            validator_set.validators()[0].id(),
            SignatureBytes::from_array([signature_byte; 64]),
            validator_set,
        )
        .unwrap()
    }

    fn header(
        parameters: &ConsensusParametersV0,
        validator_set: &ValidatorSet,
        body: &BlockBodyV0,
        receipts: &ExecutionReceiptsV0,
        kind: BlockKind,
    ) -> BlockHeader {
        BlockHeader::new(
            validator_set.genesis_hash(),
            TEST_CHAIN,
            ProtocolVersion::V0,
            validator_set.epoch(),
            View::new(9),
            Height::new(11),
            kind,
            BlockId::new([8; 32]),
            validator_set.validators()[0].id(),
            validator_set.id(),
            parameters.hash(),
            body.payload_root().unwrap(),
            StateRoot::new([10; 32]),
            receipts.receipts_root().unwrap(),
            body.evidence_root().unwrap(),
            12,
            match kind {
                BlockKind::Regular | BlockKind::EpochHandoff => None,
                BlockKind::EpochCheckpoint | BlockKind::EpochSeal1 | BlockKind::EpochSeal2 => {
                    Some(NextEpochCommitmentHash::new([11; 32]))
                }
            },
        )
        .unwrap()
    }

    #[test]
    fn application_payload_is_exact_list_of_bytes_and_empty_is_four_zero_bytes() {
        let empty = ApplicationPayloadV0::new(Vec::new()).unwrap();
        assert_eq!(empty.try_cev0_bytes().unwrap(), [0, 0, 0, 0]);
        assert_eq!(empty.transaction_count(), 0);

        let payload = ApplicationPayloadV0::new(vec![vec![b'a'], vec![0, 255]]).unwrap();
        assert_eq!(
            payload.try_cev0_bytes().unwrap(),
            [0, 0, 0, 2, 0, 0, 0, 1, b'a', 0, 0, 0, 2, 0, 255]
        );
        assert_eq!(payload.cev0_len(), 15);
    }

    #[test]
    fn event_attributes_require_utf8_and_strict_raw_key_order() {
        let a = ExecutionEventAttributeV0::new(b"a".to_vec(), b"one".to_vec()).unwrap();
        let b = ExecutionEventAttributeV0::new(b"b".to_vec(), b"two".to_vec()).unwrap();
        ExecutionEventV0::new(b"kind".to_vec(), vec![a.clone(), b]).unwrap();

        assert!(ExecutionEventV0::new(b"kind".to_vec(), vec![a.clone(), a]).is_err());
        assert!(ExecutionEventAttributeV0::new(vec![255], Vec::new()).is_err());
        assert!(ExecutionEventV0::new(vec![255], Vec::new()).is_err());
    }

    #[test]
    fn receipts_bind_one_for_one_to_exact_payload_leaves_and_size_equality_passes() {
        let payload = ApplicationPayloadV0::new(vec![b"tx-0".to_vec(), b"tx-1".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 4, 5, Vec::new())
                    .unwrap(),
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 1, 6, 7, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let exact = u32::try_from(receipts.cev0_len().unwrap()).unwrap();
        receipts.validate_max_bytes_admission(exact).unwrap();
        assert_eq!(
            receipts
                .validate_max_bytes_admission(exact - 1)
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::ReceiptListSizeExceeded
        );

        assert_eq!(
            ExecutionReceiptsV0::new_admission(
                &ApplicationPayloadV0::new(vec![b"tx-0".to_vec()]).unwrap(),
                Vec::new(),
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::ReceiptCountMismatch
        );

        let wrong_index = ExecutionReceiptCommitmentV0::new(
            1,
            ordered_leaf_digest_v0(RootKind::Payload, 0, b"tx-0").unwrap(),
            0,
            0,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            ExecutionReceiptsV0::new_admission(
                &ApplicationPayloadV0::new(vec![b"tx-0".to_vec()]).unwrap(),
                vec![wrong_index],
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::ReceiptIndexMismatch
        );

        let wrong_leaf = ExecutionReceiptCommitmentV0::new(0, [0; 32], 0, 0, Vec::new()).unwrap();
        assert_eq!(
            ExecutionReceiptsV0::new_admission(
                &ApplicationPayloadV0::new(vec![b"tx-0".to_vec()]).unwrap(),
                vec![wrong_leaf],
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::PayloadLeafMismatch
        );
    }

    #[test]
    fn root_bound_regular_body_rejects_same_header_body_substitution() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters);
        let payload = ApplicationPayloadV0::new(vec![b"authenticated".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 0, 0, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
        let header = header(&parameters, &set, &body, &receipts, BlockKind::Regular);
        let exact = crate::Block::new(
            header.clone(),
            body.application_payload().try_cev0_bytes().unwrap(),
            Vec::new(),
        )
        .unwrap();
        let facts = validate_root_bound_regular_body_v0(&exact, &set, &parameters).unwrap();
        assert_eq!(facts.block_id(), header.id());
        assert_eq!(facts.transaction_count(), 1);
        assert_eq!(facts.evidence_count(), 0);
        assert_eq!(
            facts.logical_block_size() as usize,
            exact.logical_block_size()
        );

        let substitute = ApplicationPayloadV0::new(vec![b"substitute".to_vec()])
            .unwrap()
            .try_cev0_bytes()
            .unwrap();
        let same_header = crate::Block::new(header, substitute, Vec::new()).unwrap();
        assert_eq!(
            validate_root_bound_regular_body_v0(&same_header, &set, &parameters)
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::PayloadRootMismatch
        );
    }

    #[test]
    fn double_vote_evidence_normalizes_order_has_stable_id_and_verifies_both_signatures() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let first_vote = vote(&validator_set, 11, 21, 31);
        let second_vote = vote(&validator_set, 11, 22, 32);
        let evidence = DoubleVoteEvidenceV0::from_votes(&second_vote, &first_vote).unwrap();

        assert!(evidence.first().signing_root() < evidence.second().signing_root());
        assert!(!evidence.id().is_zero());
        assert_eq!(&evidence.try_cev0_bytes().unwrap()[..2], &[0, 0]);
        evidence.verify(&validator_set, &AcceptAll).unwrap();
        assert!(evidence.verify(&validator_set, &RejectAll).is_err());
        assert!(DoubleVoteEvidenceV0::from_ordered_records(
            evidence.second().clone(),
            evidence.first().clone()
        )
        .is_err());

        let same = VoteEvidenceRecordV0::from(&first_vote);
        assert!(DoubleVoteEvidenceV0::new(same.clone(), same).is_err());
    }

    #[test]
    fn block_evidence_order_distinguishes_duplicate_and_descending_ids() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let mut evidence = vec![
            DoubleVoteEvidenceV0::from_votes(
                &vote(&validator_set, 11, 21, 31),
                &vote(&validator_set, 11, 22, 32),
            )
            .unwrap(),
            DoubleVoteEvidenceV0::from_votes(
                &vote(&validator_set, 12, 23, 33),
                &vote(&validator_set, 12, 24, 34),
            )
            .unwrap(),
        ];
        evidence.sort_by_key(DoubleVoteEvidenceV0::id);
        assert_ne!(evidence[0].id(), evidence[1].id());
        validate_evidence_order(&evidence).unwrap();

        let duplicate = vec![evidence[0].clone(), evidence[0].clone()];
        assert_eq!(
            validate_evidence_order(&duplicate).unwrap_err().code(),
            BlockValidationErrorCode::DuplicateEvidence
        );
        assert_eq!(
            BlockBodyV0::new_admission(ApplicationPayloadV0::new(Vec::new()).unwrap(), duplicate,)
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::DuplicateEvidence
        );
        evidence.reverse();
        assert_eq!(
            validate_evidence_order(&evidence).unwrap_err().code(),
            BlockValidationErrorCode::NonCanonicalEvidenceOrder
        );
        assert_eq!(
            BlockBodyV0::new_admission(ApplicationPayloadV0::new(Vec::new()).unwrap(), evidence,)
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::NonCanonicalEvidenceOrder
        );
    }

    #[test]
    fn checkpoint_static_commitments_accept_empty_and_nonempty_canonical_bodies() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let expected_state_root = StateRoot::new([10; 32]);
        let expected_commitment = NextEpochCommitmentHash::new([11; 32]);

        let empty_payload = ApplicationPayloadV0::new(Vec::new()).unwrap();
        let empty_receipts = ExecutionReceiptsV0::new(&empty_payload, Vec::new()).unwrap();
        let empty_body = BlockBodyV0::new(empty_payload, Vec::new()).unwrap();
        let empty_header = header(
            &parameters,
            &validator_set,
            &empty_body,
            &empty_receipts,
            BlockKind::EpochCheckpoint,
        );
        let empty_token = empty_body
            .validate_checkpoint_static_commitments_admission(
                &empty_header,
                &empty_receipts,
                &parameters,
                expected_state_root,
                expected_commitment,
            )
            .unwrap();
        assert_eq!(empty_token.block_id(), empty_header.id());
        assert_eq!(empty_token.payload_root(), empty_header.payload_root());
        assert_eq!(empty_token.state_root(), expected_state_root);
        assert_eq!(empty_token.receipts_root(), empty_header.receipts_root());
        assert_eq!(empty_token.evidence_root(), empty_header.evidence_root());
        assert_eq!(
            empty_token.next_epoch_commitment_hash(),
            expected_commitment
        );
        assert_eq!(empty_token.transaction_count(), 0);
        assert_eq!(empty_token.evidence_count(), 0);

        let payload = ApplicationPayloadV0::new(vec![b"checkpoint-tx".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 7, 9, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let evidence = DoubleVoteEvidenceV0::from_votes(
            &vote(&validator_set, 11, 21, 31),
            &vote(&validator_set, 11, 22, 32),
        )
        .unwrap();
        let body = BlockBodyV0::new(payload, vec![evidence]).unwrap();
        let header = header(
            &parameters,
            &validator_set,
            &body,
            &receipts,
            BlockKind::EpochCheckpoint,
        );
        let token = body
            .validate_checkpoint_static_commitments(
                &header,
                &receipts,
                &parameters,
                expected_state_root,
                expected_commitment,
            )
            .unwrap();
        assert_eq!(token.block_id(), header.id());
        assert_eq!(token.transaction_count(), 1);
        assert_eq!(token.evidence_count(), 1);
        assert_eq!(
            token.logical_block_size(),
            body.logical_block_size_v0(&header).unwrap()
        );
    }

    #[test]
    fn checkpoint_static_commitments_fail_closed_on_kind_state_commitment_and_roots() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let payload = ApplicationPayloadV0::new(vec![b"checkpoint-tx".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 7, 9, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let body = BlockBodyV0::new(payload.clone(), Vec::new()).unwrap();
        let checkpoint = header(
            &parameters,
            &validator_set,
            &body,
            &receipts,
            BlockKind::EpochCheckpoint,
        );
        let expected_state_root = StateRoot::new([10; 32]);
        let expected_commitment = NextEpochCommitmentHash::new([11; 32]);

        assert_eq!(
            BlockHeader::new(
                validator_set.genesis_hash(),
                TEST_CHAIN,
                ProtocolVersion::V0,
                validator_set.epoch(),
                View::new(9),
                Height::new(11),
                BlockKind::EpochCheckpoint,
                BlockId::new([8; 32]),
                validator_set.validators()[0].id(),
                validator_set.id(),
                parameters.hash(),
                body.payload_root().unwrap(),
                expected_state_root,
                receipts.receipts_root().unwrap(),
                body.evidence_root().unwrap(),
                12,
                None,
            )
            .unwrap_err(),
            ValidationError::InvalidBlock(
                "checkpoint/seal block must carry the next-epoch commitment"
            )
        );

        for kind in [
            BlockKind::Regular,
            BlockKind::EpochSeal1,
            BlockKind::EpochSeal2,
            BlockKind::EpochHandoff,
        ] {
            let wrong_kind = header(&parameters, &validator_set, &body, &receipts, kind);
            assert_eq!(
                body.validate_checkpoint_static_commitments_admission(
                    &wrong_kind,
                    &receipts,
                    &parameters,
                    expected_state_root,
                    expected_commitment,
                )
                .unwrap_err()
                .code(),
                BlockValidationErrorCode::NonCheckpointBlock
            );
        }
        assert_eq!(
            body.validate_checkpoint_static_commitments_admission(
                &checkpoint,
                &receipts,
                &parameters,
                StateRoot::new([12; 32]),
                expected_commitment,
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::StateRootMismatch
        );
        assert_eq!(
            body.validate_checkpoint_static_commitments_admission(
                &checkpoint,
                &receipts,
                &parameters,
                expected_state_root,
                NextEpochCommitmentHash::new([12; 32]),
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::NextEpochCommitmentMismatch
        );

        let different_payload =
            ApplicationPayloadV0::new(vec![b"different-checkpoint-tx".to_vec()]).unwrap();
        let different_receipts = ExecutionReceiptsV0::new(
            &different_payload,
            vec![ExecutionReceiptCommitmentV0::for_transaction(
                &different_payload,
                0,
                7,
                9,
                Vec::new(),
            )
            .unwrap()],
        )
        .unwrap();
        let different_body = BlockBodyV0::new(different_payload, Vec::new()).unwrap();
        assert_eq!(
            different_body
                .validate_checkpoint_static_commitments_admission(
                    &checkpoint,
                    &different_receipts,
                    &parameters,
                    expected_state_root,
                    expected_commitment,
                )
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::PayloadRootMismatch
        );

        let different_receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 99, 9, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            body.validate_checkpoint_static_commitments_admission(
                &checkpoint,
                &different_receipts,
                &parameters,
                expected_state_root,
                expected_commitment,
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::ReceiptsRootMismatch
        );

        let evidence = DoubleVoteEvidenceV0::from_votes(
            &vote(&validator_set, 11, 21, 31),
            &vote(&validator_set, 11, 22, 32),
        )
        .unwrap();
        let different_evidence_body = BlockBodyV0::new(payload, vec![evidence]).unwrap();
        assert_eq!(
            different_evidence_body
                .validate_checkpoint_static_commitments_admission(
                    &checkpoint,
                    &receipts,
                    &parameters,
                    expected_state_root,
                    expected_commitment,
                )
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::EvidenceRootMismatch
        );
    }

    #[test]
    fn ordinary_commitment_token_requires_all_static_checks_and_rejects_epoch_blocks() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let payload = ApplicationPayloadV0::new(vec![b"tx".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 1, 2, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
        let regular = header(
            &parameters,
            &validator_set,
            &body,
            &receipts,
            BlockKind::Regular,
        );
        let token = body
            .validate_ordinary_commitments(
                &regular,
                &receipts,
                &parameters,
                &validator_set,
                &AcceptAll,
            )
            .unwrap();
        assert_eq!(token.block_id(), regular.id());
        assert_eq!(token.transaction_count(), 1);
        assert_eq!(token.evidence_count(), 0);
        assert_eq!(
            token.logical_block_size(),
            body.logical_block_size_v0(&regular).unwrap()
        );
        body.validate_max_block_bytes_admission(
            &regular,
            u32::try_from(token.logical_block_size()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            body.validate_max_block_bytes_admission(
                &regular,
                u32::try_from(token.logical_block_size() - 1).unwrap(),
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::LogicalBlockSizeExceeded
        );

        let checkpoint = header(
            &parameters,
            &validator_set,
            &body,
            &receipts,
            BlockKind::EpochCheckpoint,
        );
        assert_eq!(
            body.validate_static_root_commitments_admission(&checkpoint, &receipts, &parameters)
                .unwrap_err()
                .code(),
            BlockValidationErrorCode::NonRegularBlock
        );
    }

    #[test]
    fn ordinary_commitment_token_respects_the_caller_supplied_evidence_verifier() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validator_set = validator_set(&parameters);
        let payload = ApplicationPayloadV0::new(vec![b"tx".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 1, 2, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let evidence = DoubleVoteEvidenceV0::from_votes(
            &vote(&validator_set, 11, 21, 31),
            &vote(&validator_set, 11, 22, 32),
        )
        .unwrap();
        let body = BlockBodyV0::new(payload, vec![evidence]).unwrap();
        let header = header(
            &parameters,
            &validator_set,
            &body,
            &receipts,
            BlockKind::Regular,
        );

        body.validate_ordinary_commitments(
            &header,
            &receipts,
            &parameters,
            &validator_set,
            &AcceptAll,
        )
        .unwrap();
        assert_eq!(
            body.validate_ordinary_commitments(
                &header,
                &receipts,
                &parameters,
                &validator_set,
                &RejectAll,
            )
            .unwrap_err()
            .code(),
            BlockValidationErrorCode::InvalidEvidenceSignature
        );
    }

    #[test]
    fn stable_admission_error_strings_are_frozen() {
        let expected = [
            "receipt_count_mismatch",
            "receipt_index_mismatch",
            "payload_leaf_mismatch",
            "noncanonical_evidence_order",
            "duplicate_evidence",
            "payload_root_mismatch",
            "receipts_root_mismatch",
            "evidence_root_mismatch",
            "receipt_list_size_exceeded",
            "logical_block_size_exceeded",
            "non_regular_block",
            "parameters_context_mismatch",
            "validator_set_context_mismatch",
            "invalid_evidence_signature",
            "non_checkpoint_block",
            "state_root_mismatch",
            "next_epoch_commitment_mismatch",
        ];
        for (discriminant, expected) in expected.into_iter().enumerate() {
            let code = match discriminant {
                0 => BlockValidationErrorCode::ReceiptCountMismatch,
                1 => BlockValidationErrorCode::ReceiptIndexMismatch,
                2 => BlockValidationErrorCode::PayloadLeafMismatch,
                3 => BlockValidationErrorCode::NonCanonicalEvidenceOrder,
                4 => BlockValidationErrorCode::DuplicateEvidence,
                5 => BlockValidationErrorCode::PayloadRootMismatch,
                6 => BlockValidationErrorCode::ReceiptsRootMismatch,
                7 => BlockValidationErrorCode::EvidenceRootMismatch,
                8 => BlockValidationErrorCode::ReceiptListSizeExceeded,
                9 => BlockValidationErrorCode::LogicalBlockSizeExceeded,
                10 => BlockValidationErrorCode::NonRegularBlock,
                11 => BlockValidationErrorCode::ParametersContextMismatch,
                12 => BlockValidationErrorCode::ValidatorSetContextMismatch,
                13 => BlockValidationErrorCode::InvalidEvidenceSignature,
                14 => BlockValidationErrorCode::NonCheckpointBlock,
                15 => BlockValidationErrorCode::StateRootMismatch,
                16 => BlockValidationErrorCode::NextEpochCommitmentMismatch,
                _ => unreachable!(),
            };
            assert_eq!(code as usize, discriminant);
            assert_eq!(code.as_str(), expected);
        }
    }
}
