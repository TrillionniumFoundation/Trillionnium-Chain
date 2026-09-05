//! Shared, exact CEV1 Order header, vote, and quorum-certificate types.
//!
//! This crate is deliberately below every Node/process owner. It provides
//! canonical public data and content-addressing only; decoding a value grants
//! no Safety, signing, finality, application-write, or checkpoint authority.
//! In particular, a v0 block ID cannot be passed where a v1 block ID is
//! required:
//!
//! ```compile_fail
//! use trnm_poco_order_types_v1::BlockIdV1;
//! fn requires_v1(_: BlockIdV1) {}
//! requires_v1([0_u8; 32]);
//! ```
//!
//! The manifest-bound G2 input deliberately has no field or constructor
//! argument for the ID of the block which will contain it.  That ID exists
//! only after Order application has derived all eight roots and sealed the
//! header:
//!
//! ```compile_fail
//! use trnm_poco_order_types_v1::{BlockIdV1, G2ManifestBoundInputV2};
//! let _forged = G2ManifestBoundInputV2 {
//!     candidate_block_id: BlockIdV1::new([7_u8; 32]),
//! };
//! ```

#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

mod g2_manifest_v2;

pub use g2_manifest_v2::{
    derive_g2_ordered_list_roots_v2, G2CommandCommitmentV2, G2CommandPlaneV2,
    G2ExecutionPlanDigestV2, G2InertExecutionPlanV2, G2ManifestBoundInputIdV2,
    G2ManifestBoundInputV2, G2OrderedItemV2, G2OrderedRootKindV2, G2StateCreateV2,
    G2_BATCH_REF_ITEM_KIND_V2, G2_MANIFEST_BOUND_INPUT_SCHEMA_V2, G2_PROTOCOL_BINDING_ITEM_KIND_V2,
};

pub const ORDER_BLOCK_DOMAIN_V1: &str = "trnm.poco-ai.order-block.v1";
pub const ORDER_VOTE_SIGNATURE_DOMAIN_V1: &str = "trnm.poco-ai.order-vote-signature.v1";
pub const ORDER_QC_DOMAIN_V1: &str = "trnm.poco-ai.order-qc.v1";
pub const MERKLE_LIST_ROOT_DOMAIN_V1: &str = "trnm.poco-ai.merkle-list-root.v1";

pub const MAX_CONSENSUS_STRING_BYTES_V1: usize = 1024;
pub const MAX_VALIDATOR_ID_BYTES_V1: usize = 128;
pub const MAX_SIGNATURE_BYTES_V1: usize = 128;
pub const MAX_CERTIFICATE_SIGNERS_V1: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderTypeCodecErrorCodeV1 {
    Truncated,
    TrailingBytes,
    NonCanonical,
    ParserBound,
    UnsupportedVariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderTypeCodecErrorV1 {
    code: OrderTypeCodecErrorCodeV1,
    detail: &'static str,
}

impl OrderTypeCodecErrorV1 {
    pub const fn code(&self) -> OrderTypeCodecErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for OrderTypeCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Order CEV1 codec rejected input: {}",
            self.detail
        )
    }
}

impl Error for OrderTypeCodecErrorV1 {}

pub type OrderTypeCodecResultV1<T> = Result<T, OrderTypeCodecErrorV1>;
type ResultV1<T> = OrderTypeCodecResultV1<T>;

fn reject<T>(code: OrderTypeCodecErrorCodeV1, detail: &'static str) -> ResultV1<T> {
    Err(OrderTypeCodecErrorV1 { code, detail })
}

macro_rules! typed_hash32 {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.to_bytes()
            }
        }
    };
}

typed_hash32!(BlockIdV1);
typed_hash32!(EpochDescriptorIdV1);
typed_hash32!(QuorumCertificateIdV1);
typed_hash32!(TimeoutCertificateIdV1);
typed_hash32!(UpgradePlanIdV1);
typed_hash32!(EpochHandoffIdV1);

/// Canonical CEV1 encoding implemented only by the exact shared Order types.
pub trait Cev1EncodeV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>);

    fn to_cev1_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.encode_cev1_into(&mut output);
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolContextV1 {
    pub schema_version: u16,
    pub genesis_hash: [u8; 32],
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: [u8; 32],
}

impl Cev1EncodeV1 for ProtocolContextV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        put_hash(output, self.genesis_hash);
        put_bytes(output, self.chain_id.as_bytes());
        put_u32(output, self.protocol_version);
        put_hash(output, self.stack_profile_hash);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlockKindV1 {
    FreshGenesis = 0,
    Ordinary = 1,
    EpochCheckpoint = 2,
    EpochSeal1 = 3,
    EpochSeal2 = 4,
    V0ActivationFirst = 5,
    V1HandoffFirst = 6,
}

impl TryFrom<u8> for BlockKindV1 {
    type Error = OrderTypeCodecErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FreshGenesis),
            1 => Ok(Self::Ordinary),
            2 => Ok(Self::EpochCheckpoint),
            3 => Ok(Self::EpochSeal1),
            4 => Ok(Self::EpochSeal2),
            5 => Ok(Self::V0ActivationFirst),
            6 => Ok(Self::V1HandoffFirst),
            _ => reject(
                OrderTypeCodecErrorCodeV1::UnsupportedVariant,
                "unknown BlockKindV1 tag",
            ),
        }
    }
}

impl Cev1EncodeV1 for BlockKindV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u8(output, *self as u8);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentBlockRefV1 {
    Genesis {
        derived_state_hash: [u8; 32],
        application_state_root: [u8; 32],
    },
    V1Block(BlockIdV1),
}

impl Cev1EncodeV1 for ParentBlockRefV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        match self {
            Self::Genesis {
                derived_state_hash,
                application_state_root,
            } => {
                put_u8(output, 0);
                put_hash(output, *derived_state_hash);
                put_hash(output, *application_state_root);
            }
            Self::V1Block(block_id) => {
                put_u8(output, 1);
                put_hash(output, block_id.to_bytes());
            }
        }
    }
}

/// Exact eight-root v1 header. There is intentionally no timestamp field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeaderV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub block_kind: BlockKindV1,
    pub parent: ParentBlockRefV1,
    pub proposer_id: Vec<u8>,
    pub epoch_descriptor_id: EpochDescriptorIdV1,
    pub justify_qc_id: Option<QuorumCertificateIdV1>,
    pub timeout_certificate_id: Option<TimeoutCertificateIdV1>,
    pub batch_refs_root: [u8; 32],
    pub protocol_objects_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub transaction_execution_receipts_root: [u8; 32],
    pub evidence_root: [u8; 32],
    pub consumption_rollups_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub resource_usage_root: [u8; 32],
    pub next_epoch_descriptor_id: Option<EpochDescriptorIdV1>,
    pub upgrade_plan_id: Option<UpgradePlanIdV1>,
    pub epoch_handoff_id: Option<EpochHandoffIdV1>,
}

impl BlockHeaderV1 {
    pub const fn ordered_roots(&self) -> [[u8; 32]; 8] {
        [
            self.batch_refs_root,
            self.protocol_objects_root,
            self.post_state_root,
            self.transaction_execution_receipts_root,
            self.evidence_root,
            self.consumption_rollups_root,
            self.settlement_root,
            self.resource_usage_root,
        ]
    }
}

impl Cev1EncodeV1 for BlockHeaderV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        self.context.encode_cev1_into(output);
        put_u64(output, self.epoch);
        put_u64(output, self.view);
        put_u64(output, self.height);
        self.block_kind.encode_cev1_into(output);
        self.parent.encode_cev1_into(output);
        put_bytes(output, &self.proposer_id);
        put_hash(output, self.epoch_descriptor_id.to_bytes());
        put_option_typed_hash(output, self.justify_qc_id);
        put_option_typed_hash(output, self.timeout_certificate_id);
        for root in self.ordered_roots() {
            put_hash(output, root);
        }
        put_option_typed_hash(output, self.next_epoch_descriptor_id);
        put_option_typed_hash(output, self.upgrade_plan_id);
        put_option_typed_hash(output, self.epoch_handoff_id);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusContextV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub runtime_profile_hash: [u8; 32],
    pub epoch: u64,
    pub validator_set_hash: [u8; 32],
    pub consensus_parameters_hash: [u8; 32],
    pub view: u64,
    pub message_kind: u8,
}

impl Cev1EncodeV1 for ConsensusContextV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        self.context.encode_cev1_into(output);
        put_hash(output, self.runtime_profile_hash);
        put_u64(output, self.epoch);
        put_hash(output, self.validator_set_hash);
        put_hash(output, self.consensus_parameters_hash);
        put_u64(output, self.view);
        put_u8(output, self.message_kind);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteStatementBodyV1 {
    pub schema_version: u16,
    pub consensus_context: ConsensusContextV1,
    pub block_id: BlockIdV1,
    pub height: u64,
    pub epoch_descriptor_id: EpochDescriptorIdV1,
    pub post_state_root: [u8; 32],
    pub batch_refs_root: [u8; 32],
    pub transaction_execution_receipts_root: [u8; 32],
}

impl Cev1EncodeV1 for VoteStatementBodyV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        self.consensus_context.encode_cev1_into(output);
        put_hash(output, self.block_id.to_bytes());
        put_u64(output, self.height);
        put_hash(output, self.epoch_descriptor_id.to_bytes());
        put_hash(output, self.post_state_root);
        put_hash(output, self.batch_refs_root);
        put_hash(output, self.transaction_execution_receipts_root);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteSignatureEntryV1 {
    pub voter_id: Vec<u8>,
    pub signature_scheme: u16,
    pub signature: Vec<u8>,
}

impl Cev1EncodeV1 for VoteSignatureEntryV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_bytes(output, &self.voter_id);
        put_u16(output, self.signature_scheme);
        put_bytes(output, &self.signature);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificateBodyV1 {
    pub schema_version: u16,
    pub statement: VoteStatementBodyV1,
    pub signatures: Vec<VoteSignatureEntryV1>,
}

impl Cev1EncodeV1 for QuorumCertificateBodyV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        self.statement.encode_cev1_into(output);
        put_list(output, &self.signatures);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificateV1 {
    pub body: QuorumCertificateBodyV1,
    pub quorum_certificate_id: QuorumCertificateIdV1,
}

impl Cev1EncodeV1 for QuorumCertificateV1 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        self.body.encode_cev1_into(output);
        put_hash(output, self.quorum_certificate_id.to_bytes());
    }
}

pub fn derive_block_id_v1(header: &BlockHeaderV1) -> BlockIdV1 {
    BlockIdV1::new(digest_value(ORDER_BLOCK_DOMAIN_V1, header))
}

pub fn derive_vote_signature_root_v1(statement: &VoteStatementBodyV1) -> [u8; 32] {
    digest_value(ORDER_VOTE_SIGNATURE_DOMAIN_V1, statement)
}

pub fn derive_quorum_certificate_id_v1(body: &QuorumCertificateBodyV1) -> QuorumCertificateIdV1 {
    QuorumCertificateIdV1::new(digest_value(ORDER_QC_DOMAIN_V1, body))
}

/// Empty Merkle-list root for one of the seven ordered non-state root kinds.
pub fn empty_ordered_root_v1(root_kind: u16) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(7);
    put_u16(&mut encoded, root_kind);
    put_u32(&mut encoded, 0);
    put_u8(&mut encoded, 0);
    domain_separated_digest_v1(MERKLE_LIST_ROOT_DOMAIN_V1, &encoded)
}

pub fn domain_separated_digest_v1(domain: &str, encoded: &[u8]) -> [u8; 32] {
    let domain = domain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("in-memory CEV1 domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(encoded);
    hasher.finalize().into()
}

pub fn decode_protocol_context_v1(raw: &[u8]) -> OrderTypeCodecResultV1<ProtocolContextV1> {
    decode_exact(raw, Cursor::protocol_context)
}

pub fn decode_protocol_context_prefix_v1(
    raw: &[u8],
) -> OrderTypeCodecResultV1<(ProtocolContextV1, usize)> {
    decode_prefix(raw, Cursor::protocol_context)
}

pub fn decode_block_header_v1(raw: &[u8]) -> OrderTypeCodecResultV1<BlockHeaderV1> {
    decode_exact(raw, Cursor::block_header)
}

pub fn decode_block_header_prefix_v1(raw: &[u8]) -> OrderTypeCodecResultV1<(BlockHeaderV1, usize)> {
    decode_prefix(raw, Cursor::block_header)
}

pub fn decode_vote_statement_v1(raw: &[u8]) -> OrderTypeCodecResultV1<VoteStatementBodyV1> {
    decode_exact(raw, Cursor::vote_statement)
}

pub fn decode_vote_statement_prefix_v1(
    raw: &[u8],
) -> OrderTypeCodecResultV1<(VoteStatementBodyV1, usize)> {
    decode_prefix(raw, Cursor::vote_statement)
}

pub fn decode_quorum_certificate_v1(raw: &[u8]) -> OrderTypeCodecResultV1<QuorumCertificateV1> {
    decode_exact(raw, Cursor::quorum_certificate)
}

pub fn decode_quorum_certificate_prefix_v1(
    raw: &[u8],
) -> OrderTypeCodecResultV1<(QuorumCertificateV1, usize)> {
    decode_prefix(raw, Cursor::quorum_certificate)
}

fn decode_exact<'raw, T, F>(raw: &'raw [u8], decoder: F) -> ResultV1<T>
where
    T: Cev1EncodeV1 + PartialEq,
    F: FnOnce(&mut Cursor<'raw>) -> ResultV1<T>,
{
    let (value, consumed) = decode_prefix(raw, decoder)?;
    if consumed != raw.len() {
        return reject(
            OrderTypeCodecErrorCodeV1::TrailingBytes,
            "exact Order value has trailing bytes",
        );
    }
    Ok(value)
}

fn decode_prefix<'raw, T, F>(raw: &'raw [u8], decoder: F) -> ResultV1<(T, usize)>
where
    T: Cev1EncodeV1 + PartialEq,
    F: FnOnce(&mut Cursor<'raw>) -> ResultV1<T>,
{
    let mut cursor = Cursor::new(raw);
    let value = decoder(&mut cursor)?;
    let consumed = cursor.offset;
    if value.to_cev1_bytes() != raw[..consumed] {
        return reject(
            OrderTypeCodecErrorCodeV1::NonCanonical,
            "Order value differs after exact re-encoding",
        );
    }
    Ok((value, consumed))
}

struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, length: usize) -> ResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::Truncated,
                detail: "Order cursor arithmetic overflow",
            })?;
        let value = self
            .raw
            .get(self.offset..end)
            .ok_or(OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::Truncated,
                detail: "Order value is truncated",
            })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> ResultV1<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| OrderTypeCodecErrorV1 {
            code: OrderTypeCodecErrorCodeV1::Truncated,
            detail: "fixed-width Order value is truncated",
        })
    }

    fn u8(&mut self) -> ResultV1<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> ResultV1<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> ResultV1<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> ResultV1<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bytes(&mut self, maximum: usize) -> ResultV1<Vec<u8>> {
        let length = usize::try_from(self.u32()?).map_err(|_| OrderTypeCodecErrorV1 {
            code: OrderTypeCodecErrorCodeV1::ParserBound,
            detail: "Order byte length cannot fit usize",
        })?;
        if length > maximum {
            return reject(
                OrderTypeCodecErrorCodeV1::ParserBound,
                "Order byte string exceeds parser bound",
            );
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, maximum: usize) -> ResultV1<String> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| OrderTypeCodecErrorV1 {
            code: OrderTypeCodecErrorCodeV1::NonCanonical,
            detail: "Order string is not canonical UTF-8",
        })
    }

    fn option_hash<T>(&mut self, constructor: fn([u8; 32]) -> T) -> ResultV1<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(constructor(self.array()?))),
            _ => reject(
                OrderTypeCodecErrorCodeV1::UnsupportedVariant,
                "unknown Order option tag",
            ),
        }
    }

    fn protocol_context(&mut self) -> ResultV1<ProtocolContextV1> {
        Ok(ProtocolContextV1 {
            schema_version: self.u16()?,
            genesis_hash: self.array()?,
            chain_id: self.string(MAX_CONSENSUS_STRING_BYTES_V1)?,
            protocol_version: self.u32()?,
            stack_profile_hash: self.array()?,
        })
    }

    fn parent_block_ref(&mut self) -> ResultV1<ParentBlockRefV1> {
        match self.u8()? {
            0 => Ok(ParentBlockRefV1::Genesis {
                derived_state_hash: self.array()?,
                application_state_root: self.array()?,
            }),
            1 => Ok(ParentBlockRefV1::V1Block(BlockIdV1::new(self.array()?))),
            _ => reject(
                OrderTypeCodecErrorCodeV1::UnsupportedVariant,
                "unknown ParentBlockRefV1 tag",
            ),
        }
    }

    fn block_header(&mut self) -> ResultV1<BlockHeaderV1> {
        Ok(BlockHeaderV1 {
            schema_version: self.u16()?,
            context: self.protocol_context()?,
            epoch: self.u64()?,
            view: self.u64()?,
            height: self.u64()?,
            block_kind: BlockKindV1::try_from(self.u8()?)?,
            parent: self.parent_block_ref()?,
            proposer_id: self.bytes(MAX_VALIDATOR_ID_BYTES_V1)?,
            epoch_descriptor_id: EpochDescriptorIdV1::new(self.array()?),
            justify_qc_id: self.option_hash(QuorumCertificateIdV1::new)?,
            timeout_certificate_id: self.option_hash(TimeoutCertificateIdV1::new)?,
            batch_refs_root: self.array()?,
            protocol_objects_root: self.array()?,
            post_state_root: self.array()?,
            transaction_execution_receipts_root: self.array()?,
            evidence_root: self.array()?,
            consumption_rollups_root: self.array()?,
            settlement_root: self.array()?,
            resource_usage_root: self.array()?,
            next_epoch_descriptor_id: self.option_hash(EpochDescriptorIdV1::new)?,
            upgrade_plan_id: self.option_hash(UpgradePlanIdV1::new)?,
            epoch_handoff_id: self.option_hash(EpochHandoffIdV1::new)?,
        })
    }

    fn consensus_context(&mut self) -> ResultV1<ConsensusContextV1> {
        Ok(ConsensusContextV1 {
            schema_version: self.u16()?,
            context: self.protocol_context()?,
            runtime_profile_hash: self.array()?,
            epoch: self.u64()?,
            validator_set_hash: self.array()?,
            consensus_parameters_hash: self.array()?,
            view: self.u64()?,
            message_kind: self.u8()?,
        })
    }

    fn vote_statement(&mut self) -> ResultV1<VoteStatementBodyV1> {
        Ok(VoteStatementBodyV1 {
            schema_version: self.u16()?,
            consensus_context: self.consensus_context()?,
            block_id: BlockIdV1::new(self.array()?),
            height: self.u64()?,
            epoch_descriptor_id: EpochDescriptorIdV1::new(self.array()?),
            post_state_root: self.array()?,
            batch_refs_root: self.array()?,
            transaction_execution_receipts_root: self.array()?,
        })
    }

    fn vote_signature_entry(&mut self) -> ResultV1<VoteSignatureEntryV1> {
        Ok(VoteSignatureEntryV1 {
            voter_id: self.bytes(MAX_VALIDATOR_ID_BYTES_V1)?,
            signature_scheme: self.u16()?,
            signature: self.bytes(MAX_SIGNATURE_BYTES_V1)?,
        })
    }

    fn quorum_certificate(&mut self) -> ResultV1<QuorumCertificateV1> {
        let schema_version = self.u16()?;
        let statement = self.vote_statement()?;
        let count = usize::try_from(self.u32()?).map_err(|_| OrderTypeCodecErrorV1 {
            code: OrderTypeCodecErrorCodeV1::ParserBound,
            detail: "QC signer count cannot fit usize",
        })?;
        if !(1..=MAX_CERTIFICATE_SIGNERS_V1).contains(&count) {
            return reject(
                OrderTypeCodecErrorCodeV1::ParserBound,
                "QC signer count exceeds parser bound",
            );
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(self.vote_signature_entry()?);
        }
        Ok(QuorumCertificateV1 {
            body: QuorumCertificateBodyV1 {
                schema_version,
                statement,
                signatures,
            },
            quorum_certificate_id: QuorumCertificateIdV1::new(self.array()?),
        })
    }
}

trait TypedHash32V1: Copy {
    fn to_bytes(self) -> [u8; 32];
}

macro_rules! impl_typed_hash32 {
    ($($name:ident),+ $(,)?) => {
        $(
            impl TypedHash32V1 for $name {
                fn to_bytes(self) -> [u8; 32] {
                    self.to_bytes()
                }
            }
        )+
    };
}

impl_typed_hash32!(
    BlockIdV1,
    EpochDescriptorIdV1,
    QuorumCertificateIdV1,
    TimeoutCertificateIdV1,
    UpgradePlanIdV1,
    EpochHandoffIdV1,
);

fn digest_value(domain: &str, value: &impl Cev1EncodeV1) -> [u8; 32] {
    domain_separated_digest_v1(domain, &value.to_cev1_bytes())
}

fn put_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: [u8; 32]) {
    output.extend_from_slice(&value);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(
        output,
        u32::try_from(value.len()).expect("bounded CEV1 byte length fits u32"),
    );
    output.extend_from_slice(value);
}

fn put_option_typed_hash<T: TypedHash32V1>(output: &mut Vec<u8>, value: Option<T>) {
    match value {
        None => put_u8(output, 0),
        Some(value) => {
            put_u8(output, 1);
            put_hash(output, value.to_bytes());
        }
    }
}

fn put_list(output: &mut Vec<u8>, values: &[impl Cev1EncodeV1]) {
    put_u32(
        output,
        u32::try_from(values.len()).expect("bounded CEV1 list length fits u32"),
    );
    for value in values {
        value.encode_cev1_into(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_HEX: &str = concat!(
        "010001001111111111111111111111111111111111111111111111111111111111111111",
        "0e00000074726e6d2d61692d746573742d3101000000",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "070000000000000008000000000000002a0000000000000001",
        "018181818181818181818181818181818181818181818181818181818181818181",
        "0b00000076616c696461746f722d61",
        "8282828282828282828282828282828282828282828282828282828282828282",
        "01838383838383838383838383838383838383838383838383838383838383838300",
        "bc57851d08286a6810710d5e9765b3b37ed497a9c4687d769d5fff4d8c3523a2",
        "8484848484848484848484848484848484848484848484848484848484848484",
        "8585858585858585858585858585858585858585858585858585858585858585",
        "8686868686868686868686868686868686868686868686868686868686868686",
        "8787878787878787878787878787878787878787878787878787878787878787",
        "8888888888888888888888888888888888888888888888888888888888888888",
        "8989898989898989898989898989898989898989898989898989898989898989",
        "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "000000",
    );

    fn hex(raw: &str) -> Vec<u8> {
        raw.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
                let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
                u8::try_from((high << 4) | low).expect("one byte")
            })
            .collect()
    }

    #[test]
    fn foundation_header_vector_round_trips_and_derives_typed_id() {
        let raw = hex(HEADER_HEX);
        let header = decode_block_header_v1(&raw).expect("decode exact header vector");
        assert_eq!(header.to_cev1_bytes(), raw);
        assert_eq!(header.block_kind, BlockKindV1::Ordinary);
        assert_eq!(header.ordered_roots().len(), 8);
        let expected_block_id: [u8; 32] =
            hex("7af3ef27a3b65ceb899f1e5e7776c08285ff1b8ca66af3adb7ace50157b71a4b")
                .try_into()
                .expect("hash32");
        assert_eq!(derive_block_id_v1(&header).to_bytes(), expected_block_id,);
    }

    #[test]
    fn exact_header_decoder_rejects_timestamp_or_other_trailing_bytes() {
        let mut raw = hex(HEADER_HEX);
        raw.extend_from_slice(&123_u64.to_le_bytes());
        assert_eq!(
            decode_block_header_v1(&raw)
                .expect_err("v1 header has no timestamp")
                .code(),
            OrderTypeCodecErrorCodeV1::TrailingBytes,
        );
    }

    #[test]
    fn post_state_root_substitution_changes_typed_block_id() {
        let raw = hex(HEADER_HEX);
        let mut header = decode_block_header_v1(&raw).expect("decode exact header vector");
        let original = derive_block_id_v1(&header);
        header.post_state_root[0] ^= 1;
        assert_ne!(derive_block_id_v1(&header), original);
    }

    #[test]
    fn qc_codec_round_trips_and_recomputes_id() {
        let header = decode_block_header_v1(&hex(HEADER_HEX)).expect("decode header");
        let statement = VoteStatementBodyV1 {
            schema_version: 1,
            consensus_context: ConsensusContextV1 {
                schema_version: 1,
                context: header.context.clone(),
                runtime_profile_hash: [0x33; 32],
                epoch: header.epoch,
                validator_set_hash: [0x44; 32],
                consensus_parameters_hash: [0x55; 32],
                view: header.view,
                message_kind: 1,
            },
            block_id: derive_block_id_v1(&header),
            height: header.height,
            epoch_descriptor_id: header.epoch_descriptor_id,
            post_state_root: header.post_state_root,
            batch_refs_root: header.batch_refs_root,
            transaction_execution_receipts_root: header.transaction_execution_receipts_root,
        };
        let body = QuorumCertificateBodyV1 {
            schema_version: 1,
            statement,
            signatures: vec![VoteSignatureEntryV1 {
                voter_id: b"validator-a".to_vec(),
                signature_scheme: 0,
                signature: vec![0xa0; 64],
            }],
        };
        let certificate = QuorumCertificateV1 {
            quorum_certificate_id: derive_quorum_certificate_id_v1(&body),
            body,
        };
        let raw = certificate.to_cev1_bytes();
        assert_eq!(
            decode_quorum_certificate_v1(&raw).expect("decode exact QC"),
            certificate,
        );
    }
}
