//! Independent Rust verifier for one bounded PoCO AI-native v1 Order proof.
//!
//! This crate does not depend on the Node, consensus Core, or any G2 plane. It
//! accepts only an exact CEV1 FreshGenesis trust bundle and one bounded,
//! FreshGenesis-rooted, direct-view certified chain. The legacy entry point
//! remains FreshGenesis-target-only; a second entry point also admits an
//! Ordinary target selected by the committed three-chain finality rule. The
//! trust bytes are not self-authorizing: the caller must supply an
//! independently pinned SHA-256 digest of those exact bytes.
//!
//! The returned carrier has private fields and deliberately implements neither
//! `Clone` nor `Copy`:
//!
//! ```compile_fail
//! use trnm_poco_order_finality_verifier_v1::VerifiedOrderFinalityV1;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<VerifiedOrderFinalityV1>();
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_finality_verifier_v1::VerifiedOrderFinalityV1;
//! let _forged = VerifiedOrderFinalityV1 {};
//! ```
//!
//! A separate typed receipt verifier can join an already verified Order
//! finality carrier to the registered immutable tag-50 application's exact
//! writer receipt and sparse-tree membership witness. The raw CEV1 claim is
//! generated canonically inside that typed path and is never a public
//! self-authorizing input. Its positive carrier is also non-forgeable and
//! non-duplicable:
//!
//! ```compile_fail
//! use trnm_poco_order_finality_verifier_v1::VerifiedOrderStateExecutionBindingV1;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<VerifiedOrderStateExecutionBindingV1>();
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_finality_verifier_v1::VerifiedOrderStateExecutionBindingV1;
//! let _forged = VerifiedOrderStateExecutionBindingV1 {};
//! ```

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, error::Error, fmt};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use trnm_poco_order_types_v1::{
    self as order_types, derive_block_id_v1, derive_quorum_certificate_id_v1,
    derive_vote_signature_root_v1, empty_ordered_root_v1, BlockHeaderV1 as Header, BlockIdV1,
    BlockKindV1, Cev1EncodeV1, EpochDescriptorIdV1, ParentBlockRefV1 as Parent,
    ProtocolContextV1 as ProtocolContext, QuorumCertificateIdV1,
    QuorumCertificateV1 as QuorumCertificate,
};

const VALIDATOR_SET_DEFINITION_DOMAIN: &str = "trnm.poco-ai.validator-set-definition.v1";
const VALIDATOR_SET_DOMAIN: &str = "trnm.poco-ai.validator-set.v1";
const CONSENSUS_PARAMETERS_DOMAIN: &str = "trnm.poco-ai.consensus-parameters.v1";
const EPOCH_DESCRIPTOR_DOMAIN: &str = "trnm.poco-ai.epoch-descriptor.v1";
const PROOF_DOMAIN: &str = "trnm.poco-ai.order-finality-proof.v1";

const MAX_PARSER_VALIDATORS: usize = 256;
const MAX_PARSER_CERTIFICATE_SIGNERS: usize = 256;
const MAX_PARSER_CONSENSUS_STRING_BYTES: usize = 1024;
const MAX_PARSER_SIGNATURE_BYTES: usize = 128;
// These are verifier-local admission ceilings, independent of the committed
// parameters carried inside the untrusted trust bundle. They are checked
// before either input is hashed or decoded.
const MAX_TRUST_BUNDLE_INPUT_BYTES_V1: usize = 64 * 1024;
const MAX_ORDER_FINALITY_PROOF_INPUT_BYTES_V1: usize = 256 * 1024;
const MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1: usize = 4 * 1024 * 1024;
const MAX_EXECUTION_BINDING_WITNESSES_V1: usize = 16;
const STATE_TREE_VERSION_V1: u16 = 0;
const STATE_TREE_SIBLING_COUNT_V1: usize = 256;
const STATE_KEY_DOMAIN: &str = "trnm.poco-ai.state-key.v1";
const STATE_LEAF_DOMAIN: &str = "trnm.poco-ai.state-leaf.v1";
const STATE_NODE_DOMAIN: &str = "trnm.poco-ai.state-node.v1";
/// Closed v1 `ObjectKindV1` tag for the immutable global-execution binding.
pub const GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1: u16 = 50;
/// Typed-ID domain for `GlobalExecutionBindingIdV1`.
pub const GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1: &str = "trnm.poco-ai.global-execution-binding.v1";
// The claim remains only a transport/admission envelope. Its digest never
// grants authority: the positive issuer below additionally requires the exact
// registered tag-50 value grammar and sparse membership beneath verified Order
// finality.
const EXECUTION_BINDING_CLAIM_DOMAIN_V1: &str =
    "trnm.poco-ai.global-execution-order-state-binding.claim.candidate.v1";
const REQUIRED_TRANCHE_CEV1_NESTING: u16 = 8;
const STRICT_ED25519: u16 = 0;

/// Stable rejection classes for the bounded verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderFinalityVerifyErrorCodeV1 {
    Truncated,
    TrailingBytes,
    NonCanonical,
    ParserBound,
    UnsupportedVariant,
    PinnedTrustMismatch,
    InvalidContext,
    InvalidParameters,
    InvalidValidatorSet,
    InvalidEpochDescriptor,
    InvalidGenesis,
    InvalidHeader,
    InvalidCertificate,
    InvalidSignature,
    UnderQuorum,
    InvalidChain,
    InvalidTarget,
    InvalidStateProof,
    StateRootMismatch,
    InvalidExecutionBindingClaim,
    ExecutionBindingObjectUndefined,
    /// Reserved compatibility code from the pre-writer fail-closed seam. The
    /// authoritative writer path no longer returns it for an exact receipt.
    ExecutionBindingWriterUnavailable,
}

/// Fail-closed verifier error. Details are static and contain no secret input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderFinalityVerifyErrorV1 {
    code: OrderFinalityVerifyErrorCodeV1,
    detail: &'static str,
}

impl OrderFinalityVerifyErrorV1 {
    pub const fn code(&self) -> OrderFinalityVerifyErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for OrderFinalityVerifyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bounded Order finality verification failed: {}",
            self.detail
        )
    }
}

impl Error for OrderFinalityVerifyErrorV1 {}

type ResultV1<T> = Result<T, OrderFinalityVerifyErrorV1>;
type ValidatorSetValidationV1 = ([u8; 32], [u8; 32], BTreeMap<Vec<u8>, ValidatorMember>);

fn reject<T>(code: OrderFinalityVerifyErrorCodeV1, detail: &'static str) -> ResultV1<T> {
    Err(OrderFinalityVerifyErrorV1 { code, detail })
}

fn require(
    condition: bool,
    code: OrderFinalityVerifyErrorCodeV1,
    detail: &'static str,
) -> ResultV1<()> {
    if condition {
        Ok(())
    } else {
        reject(code, detail)
    }
}

fn map_order_type_codec_error(
    error: order_types::OrderTypeCodecErrorV1,
) -> OrderFinalityVerifyErrorV1 {
    let code = match error.code() {
        order_types::OrderTypeCodecErrorCodeV1::Truncated => {
            OrderFinalityVerifyErrorCodeV1::Truncated
        }
        order_types::OrderTypeCodecErrorCodeV1::TrailingBytes => {
            OrderFinalityVerifyErrorCodeV1::TrailingBytes
        }
        order_types::OrderTypeCodecErrorCodeV1::NonCanonical => {
            OrderFinalityVerifyErrorCodeV1::NonCanonical
        }
        order_types::OrderTypeCodecErrorCodeV1::ParserBound => {
            OrderFinalityVerifyErrorCodeV1::ParserBound
        }
        order_types::OrderTypeCodecErrorCodeV1::UnsupportedVariant => {
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant
        }
    };
    OrderFinalityVerifyErrorV1 {
        code,
        detail: "shared exact Order type codec rejected input",
    }
}

/// Non-forgeable result of exact raw CEV1 parsing and bounded finality checks.
#[derive(Debug)]
pub struct VerifiedOrderFinalityV1 {
    pinned_trust_sha256: [u8; 32],
    proof_id: [u8; 32],
    chain_id: String,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    epoch: u64,
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_post_state_root: [u8; 32],
    max_cev1_value_bytes: u64,
    verified_ancestry: BTreeMap<u64, [u8; 32]>,
}

impl VerifiedOrderFinalityV1 {
    pub const fn pinned_trust_sha256(&self) -> [u8; 32] {
        self.pinned_trust_sha256
    }

    pub const fn proof_id(&self) -> [u8; 32] {
        self.proof_id
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub const fn stack_profile_hash(&self) -> [u8; 32] {
        self.stack_profile_hash
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_block_id(&self) -> [u8; 32] {
        self.finalized_block_id
    }

    pub const fn finalized_post_state_root(&self) -> [u8; 32] {
        self.finalized_post_state_root
    }

    pub const fn max_cev1_value_bytes(&self) -> u64 {
        self.max_cev1_value_bytes
    }

    /// Reports whether the exact certified prefix retained by this carrier
    /// proves one strict Order ancestor of its finalized target.
    ///
    /// This is a read-only projection of already verified ancestry. It does
    /// not accept caller-supplied proof bytes, mint a new carrier, or extend
    /// the bounded prefix beyond what the original verification retained.
    pub fn proves_strict_ancestor_v1(&self, height: u64, block_id: [u8; 32]) -> bool {
        height < self.finalized_height
            && self.verified_ancestry.get(&height).copied() == Some(block_id)
    }
}

/// Explicit test-feature issuer for downstream crash/recovery integration
/// tests. Normal builds have no synthetic finality constructor.
#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn issue_test_order_finality_v1(
    chain_id: &str,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    epoch: u64,
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_post_state_root: [u8; 32],
) -> Result<VerifiedOrderFinalityV1, OrderFinalityVerifyErrorV1> {
    let context = ProtocolContext {
        schema_version: 1,
        genesis_hash,
        chain_id: chain_id.to_owned(),
        protocol_version,
        stack_profile_hash,
    };
    validate_context(&context, None)?;
    require(
        finalized_height != 0
            && finalized_block_id != [0; 32]
            && finalized_post_state_root != [0; 32],
        OrderFinalityVerifyErrorCodeV1::InvalidTarget,
        "test finality target contains a zero authority field",
    )?;
    let mut proof_preimage = Vec::new();
    proof_preimage.extend_from_slice(b"trnm.poco-ai.test-order-finality.v1");
    proof_preimage.extend_from_slice(chain_id.as_bytes());
    proof_preimage.extend_from_slice(&genesis_hash);
    proof_preimage.extend_from_slice(&protocol_version.to_le_bytes());
    proof_preimage.extend_from_slice(&stack_profile_hash);
    proof_preimage.extend_from_slice(&epoch.to_le_bytes());
    proof_preimage.extend_from_slice(&finalized_height.to_le_bytes());
    proof_preimage.extend_from_slice(&finalized_block_id);
    proof_preimage.extend_from_slice(&finalized_post_state_root);
    let proof_id = sha256(&proof_preimage);
    let mut verified_ancestry = BTreeMap::new();
    verified_ancestry.insert(finalized_height, finalized_block_id);
    Ok(VerifiedOrderFinalityV1 {
        pinned_trust_sha256: sha256(b"trnm.poco-ai.test-order-finality.pin.v1"),
        proof_id,
        chain_id: context.chain_id,
        genesis_hash: context.genesis_hash,
        protocol_version: context.protocol_version,
        stack_profile_hash: context.stack_profile_hash,
        epoch,
        finalized_height,
        finalized_block_id,
        finalized_post_state_root,
        max_cev1_value_bytes: 4 * 1024 * 1024,
        verified_ancestry,
    })
}

/// Explicit test-feature issuer that also retains one certified strict
/// ancestor. Normal builds have no caller-supplied ancestry constructor.
#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn issue_test_order_finality_with_ancestor_v1(
    chain_id: &str,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    epoch: u64,
    finalized_height: u64,
    finalized_block_id: [u8; 32],
    finalized_post_state_root: [u8; 32],
    ancestor_height: u64,
    ancestor_block_id: [u8; 32],
) -> Result<VerifiedOrderFinalityV1, OrderFinalityVerifyErrorV1> {
    require(
        ancestor_height != 0 && ancestor_height < finalized_height && ancestor_block_id != [0; 32],
        OrderFinalityVerifyErrorCodeV1::InvalidTarget,
        "test finality strict ancestor is zero or not earlier than the target",
    )?;
    let mut verified = issue_test_order_finality_v1(
        chain_id,
        genesis_hash,
        protocol_version,
        stack_profile_hash,
        epoch,
        finalized_height,
        finalized_block_id,
        finalized_post_state_root,
    )?;
    let mut proof_preimage = Vec::new();
    proof_preimage.extend_from_slice(b"trnm.poco-ai.test-order-finality-with-ancestor.v1");
    proof_preimage.extend_from_slice(&verified.proof_id);
    proof_preimage.extend_from_slice(&ancestor_height.to_le_bytes());
    proof_preimage.extend_from_slice(&ancestor_block_id);
    verified.proof_id = sha256(&proof_preimage);
    verified
        .verified_ancestry
        .insert(ancestor_height, ancestor_block_id);
    Ok(verified)
}

/// Exact inputs to the draft v1 256-level sparse-tree membership algorithm.
///
/// This is deliberately not the complete `ApplicationStateProofV1` envelope:
/// the caller must already hold [`VerifiedOrderFinalityV1`], while schema/profile
/// authority and kind-specific inner value decoding remain separate gates. The
/// value is nevertheless required to be one strict outer
/// `ApplicationObjectValueV1` envelope for the identical typed object.
pub struct BoundedApplicationStateMembershipV1<'a> {
    pub state_tree_version: u16,
    pub object_kind: u16,
    pub object_id: [u8; 32],
    pub object_version: u64,
    pub value_bytes: &'a [u8],
    pub siblings: &'a [[u8; 32]],
}

/// Non-forgeable result binding one exact application value to the finalized
/// Order header's `post_state_root`.
#[derive(Debug)]
pub struct VerifiedApplicationStateMembershipV1 {
    order_proof_id: [u8; 32],
    finalized_block_id: [u8; 32],
    finalized_height: u64,
    state_root: [u8; 32],
    state_key: [u8; 32],
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
}

impl VerifiedApplicationStateMembershipV1 {
    pub const fn order_proof_id(&self) -> [u8; 32] {
        self.order_proof_id
    }

    pub const fn finalized_block_id(&self) -> [u8; 32] {
        self.finalized_block_id
    }

    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn state_key(&self) -> [u8; 32] {
        self.state_key
    }

    pub const fn object_kind(&self) -> u16 {
        self.object_kind
    }

    pub const fn object_id(&self) -> [u8; 32] {
        self.object_id
    }

    pub const fn object_version(&self) -> u64 {
        self.object_version
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }
}

/// Cloneable, inert bytes for one deterministic tag-50 create attempt.
///
/// This value is intentionally ordinary data, not a capability. Any caller can
/// derive it from public facts. It neither proves source-state non-membership
/// nor authorizes a JMT write, finality transition, or execution-binding
/// carrier. A future authoritative writer must consume a private Node owner,
/// prove absence of `state_key` at the exact parent root, and atomically commit
/// these bytes at `materialized_at_height` before they can become Order state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalExecutionBindingCreateMaterialV1 {
    materialized_at_height: u64,
    object_id: [u8; 32],
    state_key: [u8; 32],
    value_bytes: Vec<u8>,
}

impl GlobalExecutionBindingCreateMaterialV1 {
    pub const fn materialized_at_height(&self) -> u64 {
        self.materialized_at_height
    }

    pub const fn object_kind(&self) -> u16 {
        GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
    }

    pub const fn object_id(&self) -> [u8; 32] {
        self.object_id
    }

    pub const fn object_version(&self) -> u64 {
        0
    }

    pub const fn state_key(&self) -> [u8; 32] {
        self.state_key
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }
}

/// Derive the exact immutable tag-50 key/value material for a later height.
///
/// `materialized_at_height` is transition metadata and is deliberately not
/// part of the typed object ID: membership beneath that later finalized
/// header authenticates the materialization height. The strict inequality
/// prevents same-block self-reference. This pure function does not check
/// non-membership and cannot issue write authority.
#[allow(clippy::too_many_arguments)]
pub fn derive_global_execution_binding_create_material_v1(
    chain_id: &str,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
    materialized_at_height: u64,
) -> Result<GlobalExecutionBindingCreateMaterialV1, OrderFinalityVerifyErrorV1> {
    let context = ProtocolContext {
        schema_version: 1,
        genesis_hash,
        chain_id: chain_id.to_owned(),
        protocol_version,
        stack_profile_hash,
    };
    validate_context(&context, None)?;
    require(
        context.chain_id.len() <= MAX_PARSER_CONSENSUS_STRING_BYTES
            && candidate_height != 0
            && candidate_block_id != [0; 32]
            && candidate_composite_root != [0; 32]
            && final_execution_root != [0; 32]
            && materialized_at_height > candidate_height,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding create material is zero, oversized, or not a later height",
    )?;
    let body = GlobalExecutionBindingBodyV1 {
        schema_version: 1,
        context,
        candidate_height,
        candidate_block_id,
        candidate_composite_root,
        final_execution_root,
    };
    let object_id = digest_value(GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1, &body);
    let object = GlobalExecutionBindingV1 {
        body,
        binding_id: object_id,
    };
    let state = GlobalExecutionBindingStateV1 {
        schema_version: 1,
        binding_id: object_id,
        version: 0,
    };
    let mut immutable = Vec::new();
    object.encode(&mut immutable);
    let mut mutable = Vec::new();
    state.encode(&mut mutable);
    let value_bytes = encode_application_object_envelope_v1(
        GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1,
        object_id,
        &immutable,
        &mutable,
    );
    Ok(GlobalExecutionBindingCreateMaterialV1 {
        materialized_at_height,
        object_id,
        state_key: application_state_key_v1(GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1, object_id),
        value_bytes,
    })
}

/// Non-forgeable result of joining one exact finalized Order state root to an
/// exact global-execution candidate and terminal commitment.
#[derive(Debug)]
pub struct VerifiedOrderStateExecutionBindingV1 {
    claim_id: [u8; 32],
    order_proof_id: [u8; 32],
    chain_id: String,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    finalized_epoch: u64,
    finalized_block_id: [u8; 32],
    finalized_height: u64,
    finalized_post_state_root: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
    binding_state_key: [u8; 32],
}

impl VerifiedOrderStateExecutionBindingV1 {
    pub const fn claim_id(&self) -> [u8; 32] {
        self.claim_id
    }

    pub const fn order_proof_id(&self) -> [u8; 32] {
        self.order_proof_id
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub const fn stack_profile_hash(&self) -> [u8; 32] {
        self.stack_profile_hash
    }

    pub const fn finalized_epoch(&self) -> u64 {
        self.finalized_epoch
    }

    pub const fn finalized_block_id(&self) -> [u8; 32] {
        self.finalized_block_id
    }

    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub const fn finalized_post_state_root(&self) -> [u8; 32] {
        self.finalized_post_state_root
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub const fn candidate_block_id(&self) -> [u8; 32] {
        self.candidate_block_id
    }

    pub const fn candidate_composite_root(&self) -> [u8; 32] {
        self.candidate_composite_root
    }

    pub const fn final_execution_root(&self) -> [u8; 32] {
        self.final_execution_root
    }

    pub const fn binding_state_key(&self) -> [u8; 32] {
        self.binding_state_key
    }
}

/// Borrowed projection of one authoritative Order-state writer receipt.
///
/// This is evidence, not a capability: its fields are public so the independent
/// verifier does not depend on the writer crate. A positive carrier still
/// requires a non-forgeable [`VerifiedOrderFinalityV1`] for the exact receipt
/// height/root. The Order-state crate constructs this projection only from its
/// private, freshly read-back receipt and retains the linear terminal owner for
/// the subsequent consuming root-equality gate.
pub struct OrderStateExecutionBindingReceiptProofV1<'a> {
    pub materialized_height: u64,
    pub materialized_state_root: [u8; 32],
    pub state_tree_version: u16,
    pub object_kind: u16,
    pub object_id: [u8; 32],
    pub object_version: u64,
    pub state_key: [u8; 32],
    pub value_bytes: &'a [u8],
    pub siblings: &'a [[u8; 32]],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionBindingStateWitnessV1 {
    state_tree_version: u16,
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
    siblings: Vec<[u8; 32]>,
}

impl Canonical for ExecutionBindingStateWitnessV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        put_u16(output, self.state_tree_version);
        put_u16(output, self.object_kind);
        put_hash(output, self.object_id);
        put_u64(output, self.object_version);
        put_bytes(output, &self.value_bytes);
        put_u32(
            output,
            u32::try_from(self.siblings.len()).expect("parsed sibling count fits u32"),
        );
        for sibling in &self.siblings {
            put_hash(output, *sibling);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionBindingClaimBodyV1 {
    schema_version: u16,
    order_proof_id: [u8; 32],
    chain_id: String,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    finalized_epoch: u64,
    finalized_block_id: [u8; 32],
    finalized_height: u64,
    finalized_post_state_root: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
    witnesses: Vec<ExecutionBindingStateWitnessV1>,
}

impl Canonical for ExecutionBindingClaimBodyV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        put_hash(output, self.order_proof_id);
        put_bytes(output, self.chain_id.as_bytes());
        put_hash(output, self.genesis_hash);
        put_u32(output, self.protocol_version);
        put_hash(output, self.stack_profile_hash);
        put_u64(output, self.finalized_epoch);
        put_hash(output, self.finalized_block_id);
        put_u64(output, self.finalized_height);
        put_hash(output, self.finalized_post_state_root);
        put_u64(output, self.candidate_height);
        put_hash(output, self.candidate_block_id);
        put_hash(output, self.candidate_composite_root);
        put_hash(output, self.final_execution_root);
        put_list(output, &self.witnesses);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionBindingClaimV1 {
    body: ExecutionBindingClaimBodyV1,
    claim_id: [u8; 32],
}

/// Exact immutable body registered under ObjectKind 50.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalExecutionBindingBodyV1 {
    schema_version: u16,
    context: ProtocolContext,
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
}

impl Canonical for GlobalExecutionBindingBodyV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        self.context.encode(output);
        put_u64(output, self.candidate_height);
        put_hash(output, self.candidate_block_id);
        put_hash(output, self.candidate_composite_root);
        put_hash(output, self.final_execution_root);
    }
}

/// Exact admitted immutable object: body followed by its recomputed typed ID.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalExecutionBindingV1 {
    body: GlobalExecutionBindingBodyV1,
    binding_id: [u8; 32],
}

impl Canonical for GlobalExecutionBindingV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        self.body.encode(output);
        put_hash(output, self.binding_id);
    }
}

/// Create-once state paired with the immutable binding object.
///
/// `version` and the outer application-object version are both exactly zero;
/// there is no v1 transition that can update or delete this object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalExecutionBindingStateV1 {
    schema_version: u16,
    binding_id: [u8; 32],
    version: u64,
}

impl Canonical for GlobalExecutionBindingStateV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        put_u16(output, self.schema_version);
        put_hash(output, self.binding_id);
        put_u64(output, self.version);
    }
}

impl Canonical for ExecutionBindingClaimV1 {
    fn encode(&self, output: &mut Vec<u8>) {
        self.body.encode(output);
        put_hash(output, self.claim_id);
    }
}

/// Verify the exact draft-v1 sparse-tree membership path beneath the finalized
/// header. This proves byte membership only; callers must separately prove that
/// the kind-specific immutable and mutable payloads are valid protocol state.
pub fn verify_bounded_application_state_membership_v1(
    order: &VerifiedOrderFinalityV1,
    proof: BoundedApplicationStateMembershipV1<'_>,
) -> Result<VerifiedApplicationStateMembershipV1, OrderFinalityVerifyErrorV1> {
    require(
        proof.state_tree_version == STATE_TREE_VERSION_V1,
        OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
        "application state-tree version is unsupported",
    )?;
    require(
        proof.siblings.len() == STATE_TREE_SIBLING_COUNT_V1,
        OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
        "application membership path must contain exactly 256 siblings",
    )?;
    require(
        proof.object_id != [0; 32] && state_eligible_object_kind_v1(proof.object_kind),
        OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
        "application membership typed object is zero or not state-eligible",
    )?;
    require(
        u64::try_from(proof.value_bytes.len())
            .ok()
            .is_some_and(|length| length <= order.max_cev1_value_bytes),
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "application state value exceeds committed CEV1 bound",
    )?;
    validate_application_object_envelope_v1(proof.value_bytes, proof.object_kind, proof.object_id)?;
    let (state_key, computed_root) = application_state_membership_root_v1(&proof)?;
    require(
        computed_root == order.finalized_post_state_root,
        OrderFinalityVerifyErrorCodeV1::StateRootMismatch,
        "application membership path differs from finalized post-state root",
    )?;
    Ok(VerifiedApplicationStateMembershipV1 {
        order_proof_id: order.proof_id,
        finalized_block_id: order.finalized_block_id,
        finalized_height: order.finalized_height,
        state_root: computed_root,
        state_key,
        object_kind: proof.object_kind,
        object_id: proof.object_id,
        object_version: proof.object_version,
        value_bytes: proof.value_bytes.to_vec(),
    })
}

/// Generate the sole canonical CEV1 claim for one exact writer receipt proof.
///
/// The returned bytes are transport data, never authority. This function first
/// proves that the receipt names the exact later finalized height/root and that
/// its 256-level path authenticates the registered tag-50 value. The candidate
/// tuple is decoded from that authenticated value rather than accepted from
/// ambient caller data.
pub fn encode_order_state_execution_binding_claim_from_receipt_v1(
    order: &VerifiedOrderFinalityV1,
    receipt: &OrderStateExecutionBindingReceiptProofV1<'_>,
) -> Result<Vec<u8>, OrderFinalityVerifyErrorV1> {
    require(
        receipt.materialized_height == order.finalized_height
            && receipt.materialized_state_root == order.finalized_post_state_root
            && receipt.state_key
                == application_state_key_v1(receipt.object_kind, receipt.object_id),
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "writer receipt height, root, or typed state key differs from verified Order finality",
    )?;
    let membership = verify_bounded_application_state_membership_v1(
        order,
        BoundedApplicationStateMembershipV1 {
            state_tree_version: receipt.state_tree_version,
            object_kind: receipt.object_kind,
            object_id: receipt.object_id,
            object_version: receipt.object_version,
            value_bytes: receipt.value_bytes,
            siblings: receipt.siblings,
        },
    )?;
    require(
        membership.finalized_height() == receipt.materialized_height
            && membership.state_root() == receipt.materialized_state_root
            && membership.state_key() == receipt.state_key,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "writer receipt projection differs from authenticated membership",
    )?;
    let binding = decode_registered_execution_binding_state_object_v1(&membership)?;
    require(
        binding.candidate_height != 0
            && binding.candidate_block_id != [0; 32]
            && binding.candidate_composite_root != [0; 32]
            && binding.final_execution_root != [0; 32]
            && order
                .proves_strict_ancestor_v1(binding.candidate_height, binding.candidate_block_id),
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "writer receipt binding is not an exact strict ancestor of finalized Order state",
    )?;
    let body = ExecutionBindingClaimBodyV1 {
        schema_version: 1,
        order_proof_id: order.proof_id,
        chain_id: order.chain_id.clone(),
        genesis_hash: order.genesis_hash,
        protocol_version: order.protocol_version,
        stack_profile_hash: order.stack_profile_hash,
        finalized_epoch: order.epoch,
        finalized_block_id: order.finalized_block_id,
        finalized_height: order.finalized_height,
        finalized_post_state_root: order.finalized_post_state_root,
        candidate_height: binding.candidate_height,
        candidate_block_id: binding.candidate_block_id,
        candidate_composite_root: binding.candidate_composite_root,
        final_execution_root: binding.final_execution_root,
        witnesses: vec![ExecutionBindingStateWitnessV1 {
            state_tree_version: receipt.state_tree_version,
            object_kind: receipt.object_kind,
            object_id: receipt.object_id,
            object_version: receipt.object_version,
            value_bytes: receipt.value_bytes.to_vec(),
            siblings: receipt.siblings.to_vec(),
        }],
    };
    let claim = ExecutionBindingClaimV1 {
        claim_id: digest_value(EXECUTION_BINDING_CLAIM_DOMAIN_V1, &body),
        body,
    };
    let mut raw = Vec::new();
    claim.encode(&mut raw);
    require(
        raw.len() <= MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1,
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "canonical writer receipt claim exceeds verifier-local absolute byte bound",
    )?;
    Ok(raw)
}

/// Verify and issue the positive binding carrier from one exact typed writer
/// receipt projection and independently verified later Order finality.
///
/// The public raw-claim verifier remains available for independent transport
/// verification. This typed entry merely removes caller freedom from claim
/// construction; authority still comes exclusively from verified finality and
/// sparse membership beneath its exact `post_state_root`.
pub fn verify_order_state_execution_binding_receipt_v1(
    order: &VerifiedOrderFinalityV1,
    receipt: OrderStateExecutionBindingReceiptProofV1<'_>,
) -> Result<VerifiedOrderStateExecutionBindingV1, OrderFinalityVerifyErrorV1> {
    let raw_claim = encode_order_state_execution_binding_claim_from_receipt_v1(order, &receipt)?;
    let binding = decode_registered_execution_binding_value_v1(
        receipt.object_kind,
        receipt.object_id,
        receipt.object_version,
        receipt.value_bytes,
    )?;
    verify_order_state_execution_binding_claim_v1(
        order,
        binding.candidate_height,
        binding.candidate_block_id,
        binding.candidate_composite_root,
        binding.final_execution_root,
        &raw_claim,
    )
}

/// Verify one strict candidate execution-binding claim against an already
/// verified Order finality carrier and the caller's exact G2 commitments.
///
/// The claim is CEV1-framed and domain-addressed, but it is not self-authorizing.
/// Its single witness must be the registered immutable tag-50 execution-binding
/// object beneath the exact finalized `post_state_root`. The object binds an
/// earlier candidate: same-height inclusion is rejected because it would make
/// the candidate/application root recursively depend on itself.
#[allow(clippy::too_many_arguments)]
pub fn verify_order_state_execution_binding_claim_v1(
    order: &VerifiedOrderFinalityV1,
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
    raw_claim_cev1: &[u8],
) -> Result<VerifiedOrderStateExecutionBindingV1, OrderFinalityVerifyErrorV1> {
    require(
        raw_claim_cev1.len() <= MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1,
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "execution-binding claim exceeds verifier-local absolute byte bound",
    )?;
    let claim = decode_exact(raw_claim_cev1, Cursor::execution_binding_claim)?;
    require(
        claim.body.schema_version == 1,
        OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
        "execution-binding claim schema version is unsupported",
    )?;
    require(
        claim.claim_id == digest_value(EXECUTION_BINDING_CLAIM_DOMAIN_V1, &claim.body),
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding claim id differs",
    )?;
    require(
        claim.body.order_proof_id == order.proof_id
            && claim.body.chain_id == order.chain_id
            && claim.body.genesis_hash == order.genesis_hash
            && claim.body.protocol_version == order.protocol_version
            && claim.body.stack_profile_hash == order.stack_profile_hash
            && claim.body.finalized_epoch == order.epoch
            && claim.body.finalized_block_id == order.finalized_block_id
            && claim.body.finalized_height == order.finalized_height
            && claim.body.finalized_post_state_root == order.finalized_post_state_root,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding claim differs from verified Order authority",
    )?;
    require(
        candidate_height != 0
            && candidate_block_id != [0; 32]
            && candidate_composite_root != [0; 32]
            && final_execution_root != [0; 32]
            && claim.body.candidate_height == candidate_height
            && claim.body.candidate_block_id == candidate_block_id
            && claim.body.candidate_composite_root == candidate_composite_root
            && claim.body.final_execution_root == final_execution_root
            && order.proves_strict_ancestor_v1(candidate_height, candidate_block_id),
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding claim differs from exact finalized G2 candidate",
    )?;
    require(
        claim.body.witnesses.len() == 1,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding claim must carry exactly one registered state object",
    )?;

    let mut previous_key = None;
    let mut verified = Vec::with_capacity(claim.body.witnesses.len());
    for witness in &claim.body.witnesses {
        let key = (witness.object_kind, witness.object_id);
        require(
            previous_key.is_none_or(|previous| previous < key),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
            "execution-binding witness object keys are not strictly ordered and unique",
        )?;
        previous_key = Some(key);
        verified.push(verify_bounded_application_state_membership_v1(
            order,
            BoundedApplicationStateMembershipV1 {
                state_tree_version: witness.state_tree_version,
                object_kind: witness.object_kind,
                object_id: witness.object_id,
                object_version: witness.object_version,
                value_bytes: &witness.value_bytes,
                siblings: &witness.siblings,
            },
        )?);
    }

    let binding_state_key =
        validate_registered_execution_binding_state_object_v1(&claim.body, &verified)?;
    Ok(VerifiedOrderStateExecutionBindingV1 {
        claim_id: claim.claim_id,
        order_proof_id: claim.body.order_proof_id,
        chain_id: claim.body.chain_id,
        genesis_hash: claim.body.genesis_hash,
        protocol_version: claim.body.protocol_version,
        stack_profile_hash: claim.body.stack_profile_hash,
        finalized_epoch: claim.body.finalized_epoch,
        finalized_block_id: claim.body.finalized_block_id,
        finalized_height: claim.body.finalized_height,
        finalized_post_state_root: claim.body.finalized_post_state_root,
        candidate_height: claim.body.candidate_height,
        candidate_block_id: claim.body.candidate_block_id,
        candidate_composite_root: claim.body.candidate_composite_root,
        final_execution_root: claim.body.final_execution_root,
        binding_state_key,
    })
}

fn validate_registered_execution_binding_state_object_v1(
    claim: &ExecutionBindingClaimBodyV1,
    memberships: &[VerifiedApplicationStateMembershipV1],
) -> ResultV1<[u8; 32]> {
    let membership = memberships.first().ok_or(OrderFinalityVerifyErrorV1 {
        code: OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        detail: "execution-binding membership is absent",
    })?;
    require(
        memberships.len() == 1
            && membership.object_kind() == GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
            && membership.object_version() == 0,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding membership kind or immutable version differs",
    )?;
    let body = decode_registered_execution_binding_state_object_v1(membership)?;
    require(
        body.context.chain_id == claim.chain_id
            && body.context.genesis_hash == claim.genesis_hash
            && body.context.protocol_version == claim.protocol_version
            && body.context.stack_profile_hash == claim.stack_profile_hash
            && body.candidate_height == claim.candidate_height
            && body.candidate_block_id == claim.candidate_block_id
            && body.candidate_composite_root == claim.candidate_composite_root
            && body.final_execution_root == claim.final_execution_root,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "registered execution-binding value differs from Order/G2 authority",
    )?;
    Ok(membership.state_key())
}

fn decode_registered_execution_binding_state_object_v1(
    membership: &VerifiedApplicationStateMembershipV1,
) -> ResultV1<GlobalExecutionBindingBodyV1> {
    decode_registered_execution_binding_value_v1(
        membership.object_kind(),
        membership.object_id(),
        membership.object_version(),
        membership.value_bytes(),
    )
}

fn decode_registered_execution_binding_value_v1(
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: &[u8],
) -> ResultV1<GlobalExecutionBindingBodyV1> {
    require(
        object_kind == GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1 && object_version == 0,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "execution-binding membership kind or immutable version differs",
    )?;
    let (immutable, mutable) =
        decode_application_object_envelope_v1(value_bytes, object_kind, object_id)?;
    let object = decode_global_execution_binding_v1(immutable)?;
    let state = decode_global_execution_binding_state_v1(mutable)?;
    validate_context(&object.body.context, None)?;
    require(
        object.body.schema_version == 1
            && object.body.context.schema_version == 1
            && object.body.candidate_height != 0
            && object.body.candidate_block_id != [0; 32]
            && object.body.candidate_composite_root != [0; 32]
            && object.body.final_execution_root != [0; 32]
            && object.binding_id
                == digest_value(GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1, &object.body)
            && object.binding_id == object_id
            && state.schema_version == 1
            && state.binding_id == object.binding_id
            && state.version == 0,
        OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        "registered execution-binding value grammar or typed identity differs",
    )?;
    Ok(object.body)
}

/// Verify one pinned FreshGenesis direct, bounded three-chain-finality proof.
///
/// The pin is plain SHA-256 over `trust_bundle_cev1`; it is an operator/genesis
/// trust input, not a new consensus object ID. The proof itself is identified
/// with the specified CEV1 `OrderFinalityProofV1` domain digest.
pub fn verify_pinned_fresh_genesis_order_finality_v1(
    pinned_trust_sha256: [u8; 32],
    trust_bundle_cev1: &[u8],
    order_finality_proof_cev1: &[u8],
) -> ResultV1<VerifiedOrderFinalityV1> {
    verify_pinned_direct_order_finality_inner_v1(
        pinned_trust_sha256,
        trust_bundle_cev1,
        order_finality_proof_cev1,
        DirectFinalityTargetV1::FreshGenesisOnly,
    )
}

/// Verify one pinned, FreshGenesis-rooted, direct-view bounded finality proof.
///
/// The target is selected only by the committed three-chain finality length
/// from the exact certified chain. Every header from FreshGenesis through the
/// target is retained as private ancestry after its block ID, QC, direct
/// parent, height, and view successor have been verified. No caller-supplied
/// height/block map can add ancestry. Timeout certificates and handoffs remain
/// outside this narrow entry point.
pub fn verify_pinned_direct_order_finality_v1(
    pinned_trust_sha256: [u8; 32],
    trust_bundle_cev1: &[u8],
    order_finality_proof_cev1: &[u8],
) -> ResultV1<VerifiedOrderFinalityV1> {
    verify_pinned_direct_order_finality_inner_v1(
        pinned_trust_sha256,
        trust_bundle_cev1,
        order_finality_proof_cev1,
        DirectFinalityTargetV1::FreshGenesisOrOrdinary,
    )
}

#[derive(Clone, Copy)]
enum DirectFinalityTargetV1 {
    FreshGenesisOnly,
    FreshGenesisOrOrdinary,
}

fn verify_pinned_direct_order_finality_inner_v1(
    pinned_trust_sha256: [u8; 32],
    trust_bundle_cev1: &[u8],
    order_finality_proof_cev1: &[u8],
    target_scope: DirectFinalityTargetV1,
) -> ResultV1<VerifiedOrderFinalityV1> {
    require(
        trust_bundle_cev1.len() <= MAX_TRUST_BUNDLE_INPUT_BYTES_V1,
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "trust bundle exceeds verifier-local absolute byte bound",
    )?;
    require(
        order_finality_proof_cev1.len() <= MAX_ORDER_FINALITY_PROOF_INPUT_BYTES_V1,
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "Order proof exceeds verifier-local absolute byte bound",
    )?;
    require(
        sha256(trust_bundle_cev1) == pinned_trust_sha256,
        OrderFinalityVerifyErrorCodeV1::PinnedTrustMismatch,
        "FreshGenesis trust bundle differs from the independent pin",
    )?;
    let trust = decode_exact(trust_bundle_cev1, Cursor::trust)?;
    let proof = decode_exact(order_finality_proof_cev1, Cursor::proof)?;
    verify(trust, proof, pinned_trust_sha256, target_scope)
}

fn decode_exact<'raw, T, F>(raw: &'raw [u8], decoder: F) -> ResultV1<T>
where
    T: Canonical + PartialEq,
    F: FnOnce(&mut Cursor<'raw>) -> ResultV1<T>,
{
    let mut cursor = Cursor::new(raw);
    let value = decoder(&mut cursor)?;
    require(
        cursor.remaining() == 0,
        OrderFinalityVerifyErrorCodeV1::TrailingBytes,
        "trailing bytes",
    )?;
    let mut encoded = Vec::with_capacity(raw.len());
    value.encode(&mut encoded);
    require(
        encoded == raw,
        OrderFinalityVerifyErrorCodeV1::NonCanonical,
        "decode/re-encode bytes differ",
    )?;
    Ok(value)
}

trait Canonical {
    fn encode(&self, output: &mut Vec<u8>);
}

impl<T: Cev1EncodeV1> Canonical for T {
    fn encode(&self, output: &mut Vec<u8>) {
        self.encode_cev1_into(output);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatorMember {
    id: Vec<u8>,
    key_scheme: u16,
    public_key: Vec<u8>,
    weight: u128,
    network_identity_commitment: [u8; 32],
    safety_signer_policy_hash: [u8; 32],
    poco_economic_record_hash: [u8; 32],
}

impl Canonical for ValidatorMember {
    fn encode(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.id);
        put_u16(out, self.key_scheme);
        put_bytes(out, &self.public_key);
        put_u128(out, self.weight);
        put_hash(out, self.network_identity_commitment);
        put_hash(out, self.safety_signer_policy_hash);
        put_hash(out, self.poco_economic_record_hash);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatorDefinition {
    schema_version: u16,
    members: Vec<ValidatorMember>,
    total_weight: u128,
    quorum_threshold: u128,
}

impl Canonical for ValidatorDefinition {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        put_list(out, &self.members);
        put_u128(out, self.total_weight);
        put_u128(out, self.quorum_threshold);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatorSet {
    schema_version: u16,
    context: ProtocolContext,
    epoch: u64,
    definition: ValidatorDefinition,
}

impl Canonical for ValidatorSet {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        self.context.encode(out);
        put_u64(out, self.epoch);
        self.definition.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConsensusParameters {
    schema_version: u16,
    quorum_numerator: u16,
    quorum_denominator: u16,
    finality_chain_length: u8,
    execute_coordination_before_vote: bool,
    max_validators: u32,
    max_consensus_string_bytes: u32,
    max_cev1_nesting: u16,
    max_cev1_value_bytes: u64,
    max_signature_bytes: u32,
    max_certificate_signers: u32,
    max_epoch: u64,
    max_view: u64,
    max_height: u64,
    max_retained_views: u32,
    epoch_length_blocks: u64,
    checkpoint_offset_blocks: u64,
    seal_1_offset_blocks: u64,
    seal_2_offset_blocks: u64,
    max_block_ordered_bytes: u64,
    max_batch_refs_per_block: u32,
    max_protocol_objects_per_block: u32,
    max_transactions_per_batch: u32,
    max_transaction_bytes: u64,
    max_block_execution_units: u128,
    base_view_timeout_ms: u64,
    maximum_view_timeout_ms: u64,
    timeout_multiplier_numerator: u32,
    timeout_multiplier_denominator: u32,
    max_evidence_items_per_block: u32,
    max_evidence_bytes_per_block: u64,
}

impl Canonical for ConsensusParameters {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        put_u16(out, self.quorum_numerator);
        put_u16(out, self.quorum_denominator);
        put_u8(out, self.finality_chain_length);
        put_u8(out, u8::from(self.execute_coordination_before_vote));
        put_u32(out, self.max_validators);
        put_u32(out, self.max_consensus_string_bytes);
        put_u16(out, self.max_cev1_nesting);
        put_u64(out, self.max_cev1_value_bytes);
        put_u32(out, self.max_signature_bytes);
        put_u32(out, self.max_certificate_signers);
        put_u64(out, self.max_epoch);
        put_u64(out, self.max_view);
        put_u64(out, self.max_height);
        put_u32(out, self.max_retained_views);
        put_u64(out, self.epoch_length_blocks);
        put_u64(out, self.checkpoint_offset_blocks);
        put_u64(out, self.seal_1_offset_blocks);
        put_u64(out, self.seal_2_offset_blocks);
        put_u64(out, self.max_block_ordered_bytes);
        put_u32(out, self.max_batch_refs_per_block);
        put_u32(out, self.max_protocol_objects_per_block);
        put_u32(out, self.max_transactions_per_batch);
        put_u64(out, self.max_transaction_bytes);
        put_u128(out, self.max_block_execution_units);
        put_u64(out, self.base_view_timeout_ms);
        put_u64(out, self.maximum_view_timeout_ms);
        put_u32(out, self.timeout_multiplier_numerator);
        put_u32(out, self.timeout_multiplier_denominator);
        put_u32(out, self.max_evidence_items_per_block);
        put_u64(out, self.max_evidence_bytes_per_block);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EpochBody {
    schema_version: u16,
    context: ProtocolContext,
    epoch: u64,
    hashes: [[u8; 32]; 11],
}

impl Canonical for EpochBody {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        self.context.encode(out);
        put_u64(out, self.epoch);
        for value in self.hashes {
            put_hash(out, value);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EpochDescriptor {
    body: EpochBody,
    id: [u8; 32],
}

impl Canonical for EpochDescriptor {
    fn encode(&self, out: &mut Vec<u8>) {
        self.body.encode(out);
        put_hash(out, self.id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertifiedHeader {
    header: Header,
    block_id: BlockIdV1,
    qc: QuorumCertificate,
}

impl Canonical for CertifiedHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        put_hash(out, self.block_id.to_bytes());
        self.qc.encode(out);
        // TimeoutCertificateV1 option: this bounded tranche accepts only None.
        put_u8(out, 0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FreshGenesisAnchor {
    derived_state_hash: [u8; 32],
    header: Header,
}

impl Canonical for FreshGenesisAnchor {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, 0);
        put_hash(out, self.derived_state_hash);
        self.header.encode(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderFinalityProof {
    schema_version: u16,
    context: ProtocolContext,
    anchor: FreshGenesisAnchor,
    target_block_id: BlockIdV1,
    target_height: u64,
    target_header: Header,
    chain: Vec<CertifiedHeader>,
}

impl Canonical for OrderFinalityProof {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        self.context.encode(out);
        self.anchor.encode(out);
        put_hash(out, self.target_block_id.to_bytes());
        put_u64(out, self.target_height);
        self.target_header.encode(out);
        put_list(out, &self.chain);
        // EpochHandoffV1 list: unsupported and required empty.
        put_u32(out, 0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FreshGenesisTrustBundle {
    schema_version: u16,
    context: ProtocolContext,
    derived_state_hash: [u8; 32],
    genesis_validator_set_definition_hash: [u8; 32],
    trusted_genesis_header: Header,
    epoch_descriptor: EpochDescriptor,
    validator_set: ValidatorSet,
    parameters: ConsensusParameters,
}

impl Canonical for FreshGenesisTrustBundle {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.schema_version);
        self.context.encode(out);
        put_hash(out, self.derived_state_hash);
        put_hash(out, self.genesis_validator_set_definition_hash);
        self.trusted_genesis_header.encode(out);
        self.epoch_descriptor.encode(out);
        self.validator_set.encode(out);
        self.parameters.encode(out);
    }
}

struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> ResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::Truncated,
                detail: "cursor arithmetic overflow",
            })?;
        if end > self.raw.len() {
            return reject(OrderFinalityVerifyErrorCodeV1::Truncated, "truncated value");
        }
        let value = &self.raw[self.offset..end];
        self.offset = end;
        Ok(value)
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

    fn u128(&mut self) -> ResultV1<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> ResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::Truncated,
                detail: "fixed-width value is truncated",
            })
    }

    fn bytes(&mut self, maximum: usize) -> ResultV1<Vec<u8>> {
        let length = usize::try_from(self.u32()?).map_err(|_| OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::ParserBound,
            detail: "byte length cannot fit usize",
        })?;
        require(
            length <= maximum,
            OrderFinalityVerifyErrorCodeV1::ParserBound,
            "byte string exceeds parser bound",
        )?;
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, maximum: usize) -> ResultV1<String> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::NonCanonical,
            detail: "consensus string is not canonical UTF-8",
        })
    }

    fn context(&mut self) -> ResultV1<ProtocolContext> {
        let (value, consumed) =
            order_types::decode_protocol_context_prefix_v1(&self.raw[self.offset..])
                .map_err(map_order_type_codec_error)?;
        self.take(consumed)?;
        Ok(value)
    }

    fn validator_member(&mut self) -> ResultV1<ValidatorMember> {
        Ok(ValidatorMember {
            id: self.bytes(128)?,
            key_scheme: self.u16()?,
            public_key: self.bytes(64)?,
            weight: self.u128()?,
            network_identity_commitment: self.array()?,
            safety_signer_policy_hash: self.array()?,
            poco_economic_record_hash: self.array()?,
        })
    }

    fn validator_definition(&mut self) -> ResultV1<ValidatorDefinition> {
        let schema_version = self.u16()?;
        let count = usize::try_from(self.u32()?).expect("u32 fits usize");
        require(
            (1..=MAX_PARSER_VALIDATORS).contains(&count),
            OrderFinalityVerifyErrorCodeV1::ParserBound,
            "validator count exceeds parser bound",
        )?;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(self.validator_member()?);
        }
        Ok(ValidatorDefinition {
            schema_version,
            members,
            total_weight: self.u128()?,
            quorum_threshold: self.u128()?,
        })
    }

    fn validator_set(&mut self) -> ResultV1<ValidatorSet> {
        Ok(ValidatorSet {
            schema_version: self.u16()?,
            context: self.context()?,
            epoch: self.u64()?,
            definition: self.validator_definition()?,
        })
    }

    fn parameters(&mut self) -> ResultV1<ConsensusParameters> {
        let schema_version = self.u16()?;
        let quorum_numerator = self.u16()?;
        let quorum_denominator = self.u16()?;
        let finality_chain_length = self.u8()?;
        let execute_coordination_before_vote = match self.u8()? {
            0 => false,
            1 => true,
            _ => {
                return reject(
                    OrderFinalityVerifyErrorCodeV1::NonCanonical,
                    "boolean tag is not canonical",
                )
            }
        };
        Ok(ConsensusParameters {
            schema_version,
            quorum_numerator,
            quorum_denominator,
            finality_chain_length,
            execute_coordination_before_vote,
            max_validators: self.u32()?,
            max_consensus_string_bytes: self.u32()?,
            max_cev1_nesting: self.u16()?,
            max_cev1_value_bytes: self.u64()?,
            max_signature_bytes: self.u32()?,
            max_certificate_signers: self.u32()?,
            max_epoch: self.u64()?,
            max_view: self.u64()?,
            max_height: self.u64()?,
            max_retained_views: self.u32()?,
            epoch_length_blocks: self.u64()?,
            checkpoint_offset_blocks: self.u64()?,
            seal_1_offset_blocks: self.u64()?,
            seal_2_offset_blocks: self.u64()?,
            max_block_ordered_bytes: self.u64()?,
            max_batch_refs_per_block: self.u32()?,
            max_protocol_objects_per_block: self.u32()?,
            max_transactions_per_batch: self.u32()?,
            max_transaction_bytes: self.u64()?,
            max_block_execution_units: self.u128()?,
            base_view_timeout_ms: self.u64()?,
            maximum_view_timeout_ms: self.u64()?,
            timeout_multiplier_numerator: self.u32()?,
            timeout_multiplier_denominator: self.u32()?,
            max_evidence_items_per_block: self.u32()?,
            max_evidence_bytes_per_block: self.u64()?,
        })
    }

    fn epoch_body(&mut self) -> ResultV1<EpochBody> {
        let schema_version = self.u16()?;
        let context = self.context()?;
        let epoch = self.u64()?;
        let mut hashes = [[0; 32]; 11];
        for hash in &mut hashes {
            *hash = self.array()?;
        }
        Ok(EpochBody {
            schema_version,
            context,
            epoch,
            hashes,
        })
    }

    fn epoch_descriptor(&mut self) -> ResultV1<EpochDescriptor> {
        Ok(EpochDescriptor {
            body: self.epoch_body()?,
            id: self.array()?,
        })
    }

    fn header(&mut self) -> ResultV1<Header> {
        let (value, consumed) =
            order_types::decode_block_header_prefix_v1(&self.raw[self.offset..])
                .map_err(map_order_type_codec_error)?;
        self.take(consumed)?;
        Ok(value)
    }

    fn qc(&mut self) -> ResultV1<QuorumCertificate> {
        let (value, consumed) =
            order_types::decode_quorum_certificate_prefix_v1(&self.raw[self.offset..])
                .map_err(map_order_type_codec_error)?;
        self.take(consumed)?;
        Ok(value)
    }

    fn certified(&mut self) -> ResultV1<CertifiedHeader> {
        let value = CertifiedHeader {
            header: self.header()?,
            block_id: BlockIdV1::new(self.array()?),
            qc: self.qc()?,
        };
        require(
            self.u8()? == 0,
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
            "TimeoutCertificate is outside direct consecutive-view scope",
        )?;
        Ok(value)
    }

    fn execution_binding_state_witness(&mut self) -> ResultV1<ExecutionBindingStateWitnessV1> {
        let state_tree_version = self.u16()?;
        let object_kind = self.u16()?;
        let object_id = self.array()?;
        let object_version = self.u64()?;
        let value_bytes = self.bytes(MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1)?;
        let sibling_count =
            usize::try_from(self.u32()?).map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::ParserBound,
                detail: "execution-binding sibling count cannot fit usize",
            })?;
        require(
            sibling_count <= STATE_TREE_SIBLING_COUNT_V1,
            OrderFinalityVerifyErrorCodeV1::ParserBound,
            "execution-binding sibling count exceeds sparse-tree depth",
        )?;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(self.array()?);
        }
        Ok(ExecutionBindingStateWitnessV1 {
            state_tree_version,
            object_kind,
            object_id,
            object_version,
            value_bytes,
            siblings,
        })
    }

    fn execution_binding_claim(cursor: &mut Self) -> ResultV1<ExecutionBindingClaimV1> {
        let schema_version = cursor.u16()?;
        let order_proof_id = cursor.array()?;
        let chain_id = cursor.string(MAX_PARSER_CONSENSUS_STRING_BYTES)?;
        let genesis_hash = cursor.array()?;
        let protocol_version = cursor.u32()?;
        let stack_profile_hash = cursor.array()?;
        let finalized_epoch = cursor.u64()?;
        let finalized_block_id = cursor.array()?;
        let finalized_height = cursor.u64()?;
        let finalized_post_state_root = cursor.array()?;
        let candidate_height = cursor.u64()?;
        let candidate_block_id = cursor.array()?;
        let candidate_composite_root = cursor.array()?;
        let final_execution_root = cursor.array()?;
        let witness_count =
            usize::try_from(cursor.u32()?).map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::ParserBound,
                detail: "execution-binding witness count cannot fit usize",
            })?;
        require(
            witness_count <= MAX_EXECUTION_BINDING_WITNESSES_V1,
            OrderFinalityVerifyErrorCodeV1::ParserBound,
            "execution-binding witness count exceeds parser bound",
        )?;
        let mut witnesses = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            witnesses.push(cursor.execution_binding_state_witness()?);
        }
        Ok(ExecutionBindingClaimV1 {
            body: ExecutionBindingClaimBodyV1 {
                schema_version,
                order_proof_id,
                chain_id,
                genesis_hash,
                protocol_version,
                stack_profile_hash,
                finalized_epoch,
                finalized_block_id,
                finalized_height,
                finalized_post_state_root,
                candidate_height,
                candidate_block_id,
                candidate_composite_root,
                final_execution_root,
                witnesses,
            },
            claim_id: cursor.array()?,
        })
    }

    fn proof(cursor: &mut Self) -> ResultV1<OrderFinalityProof> {
        let schema_version = cursor.u16()?;
        let context = cursor.context()?;
        require(
            cursor.u8()? == 0,
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
            "only FreshGenesis anchor is supported",
        )?;
        let anchor = FreshGenesisAnchor {
            derived_state_hash: cursor.array()?,
            header: cursor.header()?,
        };
        let target_block_id = BlockIdV1::new(cursor.array()?);
        let target_height = cursor.u64()?;
        let target_header = cursor.header()?;
        let count = usize::try_from(cursor.u32()?).expect("u32 fits usize");
        require(
            count <= 16,
            OrderFinalityVerifyErrorCodeV1::ParserBound,
            "certified chain exceeds parser bound",
        )?;
        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            chain.push(cursor.certified()?);
        }
        require(
            cursor.u32()? == 0,
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
            "epoch handoffs are outside bounded verifier scope",
        )?;
        Ok(OrderFinalityProof {
            schema_version,
            context,
            anchor,
            target_block_id,
            target_height,
            target_header,
            chain,
        })
    }

    fn trust(cursor: &mut Self) -> ResultV1<FreshGenesisTrustBundle> {
        Ok(FreshGenesisTrustBundle {
            schema_version: cursor.u16()?,
            context: cursor.context()?,
            derived_state_hash: cursor.array()?,
            genesis_validator_set_definition_hash: cursor.array()?,
            trusted_genesis_header: cursor.header()?,
            epoch_descriptor: cursor.epoch_descriptor()?,
            validator_set: cursor.validator_set()?,
            parameters: cursor.parameters()?,
        })
    }
}

fn verify(
    trust: FreshGenesisTrustBundle,
    proof: OrderFinalityProof,
    pinned_trust_sha256: [u8; 32],
    target_scope: DirectFinalityTargetV1,
) -> ResultV1<VerifiedOrderFinalityV1> {
    require(
        trust.schema_version == 1 && proof.schema_version == 1,
        OrderFinalityVerifyErrorCodeV1::InvalidContext,
        "trust/proof schema version differs",
    )?;
    validate_context(&trust.context, None)?;
    let parameters_hash = validate_parameters(&trust.parameters)?;
    validate_context(&trust.context, Some(&trust.parameters))?;
    require(
        proof.context == trust.context,
        OrderFinalityVerifyErrorCodeV1::InvalidContext,
        "proof context differs from pinned trust context",
    )?;

    let mut encoded = Vec::new();
    trust.encode(&mut encoded);
    require(
        u64::try_from(encoded.len())
            .ok()
            .is_some_and(|len| len <= trust.parameters.max_cev1_value_bytes),
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "trust bundle exceeds committed CEV1 bound",
    )?;
    encoded.clear();
    proof.encode(&mut encoded);
    require(
        u64::try_from(encoded.len())
            .ok()
            .is_some_and(|len| len <= trust.parameters.max_cev1_value_bytes),
        OrderFinalityVerifyErrorCodeV1::ParserBound,
        "proof exceeds committed CEV1 bound",
    )?;

    let epoch_body = &trust.epoch_descriptor.body;
    require(
        epoch_body.schema_version == 1
            && epoch_body.context == trust.context
            && epoch_body.epoch <= trust.parameters.max_epoch,
        OrderFinalityVerifyErrorCodeV1::InvalidEpochDescriptor,
        "epoch descriptor context or bound differs",
    )?;
    let (validator_set_hash, definition_hash, members) = validate_validator_set(
        &trust.validator_set,
        &trust.context,
        epoch_body.epoch,
        &trust.parameters,
    )?;
    require(
        trust.genesis_validator_set_definition_hash == definition_hash,
        OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
        "genesis validator-set definition hash differs",
    )?;
    require(
        epoch_body.hashes[0] == validator_set_hash && epoch_body.hashes[1] == parameters_hash,
        OrderFinalityVerifyErrorCodeV1::InvalidEpochDescriptor,
        "epoch descriptor authority hashes differ",
    )?;
    let descriptor_id = EpochDescriptorIdV1::new(digest_value(EPOCH_DESCRIPTOR_DOMAIN, epoch_body));
    require(
        trust.epoch_descriptor.id == descriptor_id.to_bytes(),
        OrderFinalityVerifyErrorCodeV1::InvalidEpochDescriptor,
        "epoch descriptor ID differs",
    )?;

    let genesis = &trust.trusted_genesis_header;
    validate_header(genesis, &trust.parameters)?;
    require(
        genesis.context == trust.context
            && genesis.epoch == epoch_body.epoch
            && genesis.epoch_descriptor_id == descriptor_id,
        OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
        "trusted genesis authority differs",
    )?;
    validate_fresh_genesis(genesis, trust.derived_state_hash)?;
    require(
        members.contains_key(genesis.proposer_id.as_slice()),
        OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
        "trusted genesis proposer is not a validator",
    )?;
    let genesis_id = derive_block_id_v1(genesis);
    require(
        proof.anchor.derived_state_hash == trust.derived_state_hash
            && proof.anchor.header == *genesis,
        OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
        "proof anchor differs from pinned genesis",
    )?;
    require(
        (3..=16).contains(&proof.chain.len()),
        OrderFinalityVerifyErrorCodeV1::InvalidChain,
        "bounded direct verifier requires three to sixteen certified headers",
    )?;
    validate_retained_view_bound(proof.chain.len(), trust.parameters.max_retained_views)?;

    let mut block_ids = Vec::with_capacity(proof.chain.len());
    let mut qc_ids = Vec::with_capacity(proof.chain.len());
    for (index, certified) in proof.chain.iter().enumerate() {
        let header = &certified.header;
        validate_header(header, &trust.parameters)?;
        require(
            header.context == trust.context
                && header.epoch == epoch_body.epoch
                && header.epoch_descriptor_id == descriptor_id,
            OrderFinalityVerifyErrorCodeV1::InvalidHeader,
            "certified header authority differs",
        )?;
        require(
            header.next_epoch_descriptor_id.is_none()
                && header.upgrade_plan_id.is_none()
                && header.epoch_handoff_id.is_none()
                && header.timeout_certificate_id.is_none(),
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
            "header sidecar or timeout is outside bounded scope",
        )?;
        require(
            members.contains_key(header.proposer_id.as_slice()),
            OrderFinalityVerifyErrorCodeV1::InvalidHeader,
            "certified proposer is not a validator",
        )?;
        require(
            (index == 0 && header.block_kind == BlockKindV1::FreshGenesis)
                || (index > 0 && header.block_kind == BlockKindV1::Ordinary),
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant,
            "bounded chain kind is not FreshGenesis/Ordinary",
        )?;
        let (block_id, qc_id) = verify_qc(
            certified,
            &trust.context,
            epoch_body,
            descriptor_id,
            validator_set_hash,
            parameters_hash,
            &trust.parameters,
            &members,
            trust.validator_set.definition.quorum_threshold,
        )?;
        block_ids.push(block_id);
        qc_ids.push(qc_id);
    }
    require(
        proof.chain[0].header == *genesis && block_ids[0] == genesis_id,
        OrderFinalityVerifyErrorCodeV1::InvalidChain,
        "first certified header differs from trusted genesis",
    )?;
    for index in 1..proof.chain.len() {
        let previous = &proof.chain[index - 1].header;
        let current = &proof.chain[index].header;
        require(
            current.parent == Parent::V1Block(block_ids[index - 1])
                && current.justify_qc_id == Some(qc_ids[index - 1]),
            OrderFinalityVerifyErrorCodeV1::InvalidChain,
            "parent or justify QC differs",
        )?;
        require(
            previous.height.checked_add(1) == Some(current.height)
                && previous.view.checked_add(1) == Some(current.view),
            OrderFinalityVerifyErrorCodeV1::InvalidChain,
            "height/view is not a direct consecutive successor",
        )?;
    }
    let target_index = proof
        .chain
        .len()
        .checked_sub(usize::from(trust.parameters.finality_chain_length))
        .ok_or(OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::InvalidTarget,
            detail: "certified chain is shorter than committed finality length",
        })?;
    let target = &proof.chain[target_index].header;
    require(
        proof.target_block_id == block_ids[target_index]
            && proof.target_height == target.height
            && proof.target_header == *target,
        OrderFinalityVerifyErrorCodeV1::InvalidTarget,
        "proof target differs from the committed three-chain position",
    )?;
    require(
        matches!(target_scope, DirectFinalityTargetV1::FreshGenesisOrOrdinary) || target_index == 0,
        OrderFinalityVerifyErrorCodeV1::InvalidTarget,
        "FreshGenesis-only entry point rejects an Ordinary target",
    )?;
    require(
        proof.chain[target_index].header.view < proof.chain[target_index + 1].header.view
            && proof.chain[target_index + 1].header.view
                < proof.chain[target_index + 2].header.view,
        OrderFinalityVerifyErrorCodeV1::InvalidChain,
        "finality QC views are not strictly ordered",
    )?;
    let proof_id = digest_value(PROOF_DOMAIN, &proof);
    let mut verified_ancestry = BTreeMap::<u64, [u8; 32]>::new();
    for (header, block_id) in proof
        .chain
        .iter()
        .map(|certified| &certified.header)
        .zip(block_ids.iter().copied())
        .take(target_index + 1)
    {
        require(
            verified_ancestry
                .insert(header.height, block_id.to_bytes())
                .is_none(),
            OrderFinalityVerifyErrorCodeV1::InvalidChain,
            "certified ancestry repeats a height",
        )?;
    }
    Ok(VerifiedOrderFinalityV1 {
        pinned_trust_sha256,
        proof_id,
        chain_id: trust.context.chain_id,
        genesis_hash: trust.context.genesis_hash,
        protocol_version: trust.context.protocol_version,
        stack_profile_hash: trust.context.stack_profile_hash,
        epoch: epoch_body.epoch,
        finalized_height: target.height,
        finalized_block_id: block_ids[target_index].to_bytes(),
        finalized_post_state_root: target.post_state_root,
        max_cev1_value_bytes: trust.parameters.max_cev1_value_bytes,
        verified_ancestry,
    })
}

fn validate_retained_view_bound(chain_len: usize, max_retained_views: u32) -> ResultV1<()> {
    require(
        chain_len <= usize::try_from(max_retained_views).unwrap_or(0),
        OrderFinalityVerifyErrorCodeV1::InvalidChain,
        "certified chain exceeds committed retained-view bound",
    )
}

fn validate_context(
    context: &ProtocolContext,
    parameters: Option<&ConsensusParameters>,
) -> ResultV1<()> {
    require(
        context.schema_version == 1
            && context.protocol_version == 1
            && !context.chain_id.is_empty()
            && context.genesis_hash != [0; 32]
            && context.stack_profile_hash != [0; 32],
        OrderFinalityVerifyErrorCodeV1::InvalidContext,
        "protocol context is invalid",
    )?;
    if let Some(parameters) = parameters {
        require(
            context.chain_id.len()
                <= usize::try_from(parameters.max_consensus_string_bytes).unwrap_or(usize::MAX),
            OrderFinalityVerifyErrorCodeV1::InvalidContext,
            "chain ID exceeds committed bound",
        )?;
    }
    Ok(())
}

fn validate_parameters(parameters: &ConsensusParameters) -> ResultV1<[u8; 32]> {
    let positive = [
        u128::from(parameters.max_validators),
        u128::from(parameters.max_consensus_string_bytes),
        u128::from(parameters.max_cev1_nesting),
        u128::from(parameters.max_cev1_value_bytes),
        u128::from(parameters.max_signature_bytes),
        u128::from(parameters.max_certificate_signers),
        u128::from(parameters.max_epoch),
        u128::from(parameters.max_view),
        u128::from(parameters.max_height),
        u128::from(parameters.max_retained_views),
        u128::from(parameters.epoch_length_blocks),
        u128::from(parameters.checkpoint_offset_blocks),
        u128::from(parameters.seal_1_offset_blocks),
        u128::from(parameters.seal_2_offset_blocks),
        u128::from(parameters.max_block_ordered_bytes),
        u128::from(parameters.max_batch_refs_per_block),
        u128::from(parameters.max_protocol_objects_per_block),
        u128::from(parameters.max_transactions_per_batch),
        u128::from(parameters.max_transaction_bytes),
        parameters.max_block_execution_units,
        u128::from(parameters.base_view_timeout_ms),
        u128::from(parameters.maximum_view_timeout_ms),
        u128::from(parameters.timeout_multiplier_numerator),
        u128::from(parameters.timeout_multiplier_denominator),
        u128::from(parameters.max_evidence_items_per_block),
        u128::from(parameters.max_evidence_bytes_per_block),
    ];
    require(
        parameters.schema_version == 1
            && parameters.quorum_numerator == 2
            && parameters.quorum_denominator == 3
            && parameters.finality_chain_length == 3
            && parameters.execute_coordination_before_vote
            && positive.into_iter().all(|value| value > 0),
        OrderFinalityVerifyErrorCodeV1::InvalidParameters,
        "committed consensus parameters are invalid",
    )?;
    require(
        usize::try_from(parameters.max_validators)
            .ok()
            .is_some_and(|value| value <= MAX_PARSER_VALIDATORS)
            && usize::try_from(parameters.max_certificate_signers)
                .ok()
                .is_some_and(|value| value <= MAX_PARSER_CERTIFICATE_SIGNERS)
            && usize::try_from(parameters.max_consensus_string_bytes)
                .ok()
                .is_some_and(|value| value <= MAX_PARSER_CONSENSUS_STRING_BYTES)
            && usize::try_from(parameters.max_signature_bytes)
                .ok()
                .is_some_and(|value| value <= MAX_PARSER_SIGNATURE_BYTES)
            && parameters.max_certificate_signers >= parameters.max_validators
            && parameters.max_cev1_nesting >= REQUIRED_TRANCHE_CEV1_NESTING,
        OrderFinalityVerifyErrorCodeV1::InvalidParameters,
        "committed bounds exceed verifier support",
    )?;
    require(
        parameters.checkpoint_offset_blocks.checked_add(1) == Some(parameters.seal_1_offset_blocks)
            && parameters.seal_1_offset_blocks.checked_add(1)
                == Some(parameters.seal_2_offset_blocks)
            && parameters.seal_2_offset_blocks.checked_add(1)
                == Some(parameters.epoch_length_blocks)
            && parameters.base_view_timeout_ms <= parameters.maximum_view_timeout_ms
            && parameters.timeout_multiplier_numerator >= parameters.timeout_multiplier_denominator,
        OrderFinalityVerifyErrorCodeV1::InvalidParameters,
        "committed schedule or timeout parameters are invalid",
    )?;
    Ok(digest_value(CONSENSUS_PARAMETERS_DOMAIN, parameters))
}

fn validate_validator_set(
    set: &ValidatorSet,
    context: &ProtocolContext,
    epoch: u64,
    parameters: &ConsensusParameters,
) -> ResultV1<ValidatorSetValidationV1> {
    require(
        set.schema_version == 1
            && set.context == *context
            && set.epoch == epoch
            && set.definition.schema_version == 1,
        OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
        "validator-set context differs",
    )?;
    require(
        !set.definition.members.is_empty()
            && set.definition.members.len()
                <= usize::try_from(parameters.max_validators).unwrap_or(0),
        OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
        "validator count differs",
    )?;
    let mut members = BTreeMap::new();
    let mut prior_id: Option<&[u8]> = None;
    let mut keys = std::collections::BTreeSet::new();
    let mut total = 0u128;
    for member in &set.definition.members {
        require(
            !member.id.is_empty()
                && prior_id.is_none_or(|prior| prior < member.id.as_slice())
                && member.key_scheme == STRICT_ED25519
                && member.public_key.len() == 32
                && member.weight > 0,
            OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
            "validator ordering/key/weight is invalid",
        )?;
        let key_bytes: [u8; 32] =
            member
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| OrderFinalityVerifyErrorV1 {
                    code: OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
                    detail: "validator public key shape differs",
                })?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
            detail: "validator public key does not decode",
        })?;
        require(
            !key.is_weak() && keys.insert(key_bytes),
            OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
            "validator public key is weak or repeated",
        )?;
        total = total
            .checked_add(member.weight)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
                detail: "validator total weight overflows",
            })?;
        prior_id = Some(&member.id);
        members.insert(member.id.clone(), member.clone());
    }
    require(
        total <= u128::MAX / 2,
        OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
        "quorum multiplication could overflow",
    )?;
    let threshold = total
        .checked_mul(u128::from(parameters.quorum_numerator))
        .and_then(|value| value.checked_div(u128::from(parameters.quorum_denominator)))
        .and_then(|value| value.checked_add(1))
        .ok_or(OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
            detail: "quorum threshold arithmetic failed",
        })?;
    require(
        set.definition.total_weight == total && set.definition.quorum_threshold == threshold,
        OrderFinalityVerifyErrorCodeV1::InvalidValidatorSet,
        "committed validator weights/quorum differ",
    )?;
    Ok((
        digest_value(VALIDATOR_SET_DOMAIN, set),
        digest_value(VALIDATOR_SET_DEFINITION_DOMAIN, &set.definition),
        members,
    ))
}

fn validate_header(header: &Header, parameters: &ConsensusParameters) -> ResultV1<()> {
    validate_context(&header.context, Some(parameters))?;
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    require(
        header.schema_version == 1
            && header.epoch <= parameters.max_epoch
            && header.view <= parameters.max_view
            && header.height <= parameters.max_height
            && !header.proposer_id.is_empty()
            && u64::try_from(encoded.len())
                .ok()
                .is_some_and(|length| length <= parameters.max_cev1_value_bytes),
        OrderFinalityVerifyErrorCodeV1::InvalidHeader,
        "header shape or committed bound differs",
    )
}

fn validate_fresh_genesis(header: &Header, derived_state_hash: [u8; 32]) -> ResultV1<()> {
    let (parent_derived, application_state_root) = match &header.parent {
        Parent::Genesis {
            derived_state_hash,
            application_state_root,
        } => (*derived_state_hash, *application_state_root),
        Parent::V1Block(_) => {
            return reject(
                OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
                "FreshGenesis parent is not GenesisAnchor",
            )
        }
    };
    require(
        header.epoch == 0
            && header.view == 1
            && header.block_kind == BlockKindV1::FreshGenesis
            && parent_derived == derived_state_hash
            && header.post_state_root == application_state_root
            && header.justify_qc_id.is_none()
            && header.timeout_certificate_id.is_none()
            && header.next_epoch_descriptor_id.is_none()
            && header.upgrade_plan_id.is_none()
            && header.epoch_handoff_id.is_none(),
        OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
        "FreshGenesis fields differ",
    )?;
    let ordered_roots = [
        (0, header.batch_refs_root),
        (1, header.protocol_objects_root),
        (2, header.transaction_execution_receipts_root),
        (3, header.evidence_root),
        (4, header.consumption_rollups_root),
        (5, header.settlement_root),
        (6, header.resource_usage_root),
    ];
    for (kind, root) in ordered_roots {
        require(
            root == empty_ordered_root_v1(kind),
            OrderFinalityVerifyErrorCodeV1::InvalidGenesis,
            "FreshGenesis non-state root is not empty",
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_qc(
    certified: &CertifiedHeader,
    context: &ProtocolContext,
    epoch_body: &EpochBody,
    descriptor_id: EpochDescriptorIdV1,
    validator_set_hash: [u8; 32],
    parameters_hash: [u8; 32],
    parameters: &ConsensusParameters,
    members: &BTreeMap<Vec<u8>, ValidatorMember>,
    threshold: u128,
) -> ResultV1<(BlockIdV1, QuorumCertificateIdV1)> {
    let block_id = derive_block_id_v1(&certified.header);
    require(
        certified.block_id == block_id,
        OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
        "certified block ID differs",
    )?;
    let qc_id = derive_quorum_certificate_id_v1(&certified.qc.body);
    require(
        certified.qc.body.schema_version == 1 && certified.qc.quorum_certificate_id == qc_id,
        OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
        "QC version or ID differs",
    )?;
    let vote = &certified.qc.body.statement;
    let consensus = &vote.consensus_context;
    require(
        vote.schema_version == 1
            && consensus.schema_version == 1
            && consensus.message_kind == 1
            && consensus.context == *context
            && consensus.epoch == epoch_body.epoch
            && consensus.runtime_profile_hash == epoch_body.hashes[2]
            && consensus.validator_set_hash == validator_set_hash
            && consensus.consensus_parameters_hash == parameters_hash
            && consensus.view == certified.header.view,
        OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
        "Vote authority differs",
    )?;
    require(
        vote.block_id == block_id
            && vote.height == certified.header.height
            && vote.epoch_descriptor_id == descriptor_id
            && vote.post_state_root == certified.header.post_state_root
            && vote.batch_refs_root == certified.header.batch_refs_root
            && vote.transaction_execution_receipts_root
                == certified.header.transaction_execution_receipts_root,
        OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
        "Vote statement differs from header",
    )?;
    require(
        certified.qc.body.signatures.len()
            <= usize::try_from(parameters.max_certificate_signers).unwrap_or(0),
        OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
        "QC signer count exceeds committed bound",
    )?;
    let vote_root = derive_vote_signature_root_v1(vote);
    let mut weight = 0u128;
    let mut prior: Option<&[u8]> = None;
    for entry in &certified.qc.body.signatures {
        require(
            prior.is_none_or(|value| value < entry.voter_id.as_slice()),
            OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
            "QC signers are not strictly ordered and unique",
        )?;
        let member = members
            .get(&entry.voter_id)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
                detail: "QC signer is not a validator",
            })?;
        require(
            entry.signature_scheme == STRICT_ED25519
                && entry.signature.len() == 64
                && entry.signature.len()
                    <= usize::try_from(parameters.max_signature_bytes).unwrap_or(0),
            OrderFinalityVerifyErrorCodeV1::InvalidSignature,
            "QC signature scheme or shape differs",
        )?;
        let public_key: [u8; 32] =
            member
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| OrderFinalityVerifyErrorV1 {
                    code: OrderFinalityVerifyErrorCodeV1::InvalidSignature,
                    detail: "validator public key shape differs",
                })?;
        let signature_bytes: [u8; 64] =
            entry
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| OrderFinalityVerifyErrorV1 {
                    code: OrderFinalityVerifyErrorCodeV1::InvalidSignature,
                    detail: "QC signature shape differs",
                })?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidSignature,
                detail: "validator public key cannot verify",
            })?;
        require(
            verifying_key
                .verify_strict(&vote_root, &Signature::from_bytes(&signature_bytes))
                .is_ok(),
            OrderFinalityVerifyErrorCodeV1::InvalidSignature,
            "QC signature verification failed",
        )?;
        weight = weight
            .checked_add(member.weight)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidCertificate,
                detail: "QC weight overflows",
            })?;
        prior = Some(&entry.voter_id);
    }
    require(
        weight >= threshold,
        OrderFinalityVerifyErrorCodeV1::UnderQuorum,
        "QC weight is below threshold",
    )?;
    Ok((block_id, qc_id))
}

fn state_eligible_object_kind_v1(object_kind: u16) -> bool {
    matches!(
        object_kind,
        0..=9 | 14 | 18..=20 | 44..=GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
    )
}

fn application_state_key_v1(object_kind: u16, object_id: [u8; 32]) -> [u8; 32] {
    let mut typed_object = Vec::with_capacity(34);
    put_u16(&mut typed_object, object_kind);
    put_hash(&mut typed_object, object_id);
    digest(STATE_KEY_DOMAIN, &typed_object)
}

fn encode_application_object_envelope_v1(
    object_kind: u16,
    object_id: [u8; 32],
    immutable: &[u8],
    mutable: &[u8],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(46 + immutable.len() + mutable.len());
    put_u16(&mut value, 1);
    put_u16(&mut value, object_kind);
    put_hash(&mut value, object_id);
    put_bytes(&mut value, immutable);
    put_bytes(&mut value, mutable);
    value
}

fn validate_application_object_envelope_v1(
    raw: &[u8],
    expected_kind: u16,
    expected_id: [u8; 32],
) -> ResultV1<()> {
    decode_application_object_envelope_v1(raw, expected_kind, expected_id).map(|_| ())
}

fn decode_application_object_envelope_v1(
    raw: &[u8],
    expected_kind: u16,
    expected_id: [u8; 32],
) -> ResultV1<(&[u8], &[u8])> {
    let mut cursor = StateValueCursorV1 { raw, offset: 0 };
    let schema_version = cursor.u16()?;
    let object_kind = cursor.u16()?;
    let object_id = cursor.array()?;
    let immutable = cursor.bytes()?;
    let mutable = cursor.bytes()?;
    require(
        cursor.offset == raw.len(),
        OrderFinalityVerifyErrorCodeV1::TrailingBytes,
        "application object envelope has trailing bytes",
    )?;
    require(
        schema_version == 1
            && object_kind == expected_kind
            && object_id == expected_id
            && !immutable.is_empty()
            && !mutable.is_empty(),
        OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
        "application object envelope identity or payload shape differs",
    )?;
    Ok((immutable, mutable))
}

fn decode_global_execution_binding_v1(raw: &[u8]) -> ResultV1<GlobalExecutionBindingV1> {
    let mut cursor = StateValueCursorV1 { raw, offset: 0 };
    let body = GlobalExecutionBindingBodyV1 {
        schema_version: cursor.u16()?,
        context: ProtocolContext {
            schema_version: cursor.u16()?,
            genesis_hash: cursor.array()?,
            chain_id: cursor.consensus_string()?,
            protocol_version: cursor.u32()?,
            stack_profile_hash: cursor.array()?,
        },
        candidate_height: cursor.u64()?,
        candidate_block_id: cursor.array()?,
        candidate_composite_root: cursor.array()?,
        final_execution_root: cursor.array()?,
    };
    let binding_id = cursor.array()?;
    require(
        cursor.offset == raw.len(),
        OrderFinalityVerifyErrorCodeV1::TrailingBytes,
        "global-execution binding immutable bytes have trailing data",
    )?;
    let value = GlobalExecutionBindingV1 { body, binding_id };
    let mut encoded = Vec::with_capacity(raw.len());
    value.encode(&mut encoded);
    require(
        encoded == raw,
        OrderFinalityVerifyErrorCodeV1::NonCanonical,
        "global-execution binding immutable bytes are non-canonical",
    )?;
    Ok(value)
}

fn decode_global_execution_binding_state_v1(raw: &[u8]) -> ResultV1<GlobalExecutionBindingStateV1> {
    let mut cursor = StateValueCursorV1 { raw, offset: 0 };
    let value = GlobalExecutionBindingStateV1 {
        schema_version: cursor.u16()?,
        binding_id: cursor.array()?,
        version: cursor.u64()?,
    };
    require(
        cursor.offset == raw.len(),
        OrderFinalityVerifyErrorCodeV1::TrailingBytes,
        "global-execution binding state bytes have trailing data",
    )?;
    let mut encoded = Vec::with_capacity(raw.len());
    value.encode(&mut encoded);
    require(
        encoded == raw,
        OrderFinalityVerifyErrorCodeV1::NonCanonical,
        "global-execution binding state bytes are non-canonical",
    )?;
    Ok(value)
}

fn application_state_membership_root_v1(
    proof: &BoundedApplicationStateMembershipV1<'_>,
) -> ResultV1<([u8; 32], [u8; 32])> {
    let state_key = application_state_key_v1(proof.object_kind, proof.object_id);

    let mut leaf = Vec::with_capacity(42 + proof.value_bytes.len());
    put_hash(&mut leaf, state_key);
    put_u16(&mut leaf, proof.object_kind);
    put_u64(&mut leaf, proof.object_version);
    put_bytes(&mut leaf, proof.value_bytes);
    let mut running = digest(STATE_LEAF_DOMAIN, &leaf);

    for (level, sibling) in proof.siblings.iter().enumerate() {
        let bit_index = 255usize
            .checked_sub(level)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
                detail: "application membership level overflows key bits",
            })?;
        let byte = state_key[bit_index / 8];
        let bit = (byte >> (7 - (bit_index % 8))) & 1;
        let (left, right) = if bit == 0 {
            (running, *sibling)
        } else {
            (*sibling, running)
        };
        let mut node = Vec::with_capacity(66);
        put_u16(
            &mut node,
            u16::try_from(level).map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
                detail: "application membership level exceeds u16",
            })?,
        );
        put_hash(&mut node, left);
        put_hash(&mut node, right);
        running = digest(STATE_NODE_DOMAIN, &node);
    }
    Ok((state_key, running))
}

struct StateValueCursorV1<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> StateValueCursorV1<'a> {
    fn take(&mut self, length: usize) -> ResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::Truncated,
                detail: "application object envelope offset overflows",
            })?;
        let value = self
            .raw
            .get(self.offset..end)
            .ok_or(OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::Truncated,
                detail: "application object envelope is truncated",
            })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> ResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| OrderFinalityVerifyErrorV1 {
                code: OrderFinalityVerifyErrorCodeV1::Truncated,
                detail: "application object fixed field is truncated",
            })
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

    fn consensus_string(&mut self) -> ResultV1<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::NonCanonical,
            detail: "global-execution binding chain ID is not UTF-8",
        })
    }

    fn bytes(&mut self) -> ResultV1<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| OrderFinalityVerifyErrorV1 {
            code: OrderFinalityVerifyErrorCodeV1::ParserBound,
            detail: "application object byte length cannot fit usize",
        })?;
        self.take(length)
    }
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn digest_value(domain: &str, value: &impl Canonical) -> [u8; 32] {
    let mut encoded = Vec::new();
    value.encode(&mut encoded);
    digest(domain, &encoded)
}

fn digest(domain: &str, encoded: &[u8]) -> [u8; 32] {
    let domain = domain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static domain fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(encoded);
    hasher.finalize().into()
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

fn put_u128(output: &mut Vec<u8>, value: u128) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: [u8; 32]) {
    output.extend_from_slice(&value);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(
        output,
        u32::try_from(value.len()).expect("parsed CEV1 length fits u32"),
    );
    output.extend_from_slice(value);
}

fn put_list(output: &mut Vec<u8>, values: &[impl Canonical]) {
    put_u32(
        output,
        u32::try_from(values.len()).expect("parsed CEV1 list length fits u32"),
    );
    for value in values {
        value.encode(output);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        application_state_membership_root_v1, derive_global_execution_binding_create_material_v1,
        digest, digest_value, encode_order_state_execution_binding_claim_from_receipt_v1,
        put_bytes, put_hash, put_u16, put_u64, sha256, validate_retained_view_bound,
        verify_bounded_application_state_membership_v1,
        verify_order_state_execution_binding_claim_v1,
        verify_order_state_execution_binding_receipt_v1, verify_pinned_direct_order_finality_v1,
        verify_pinned_fresh_genesis_order_finality_v1, BoundedApplicationStateMembershipV1,
        Canonical, ExecutionBindingClaimBodyV1, ExecutionBindingClaimV1,
        ExecutionBindingStateWitnessV1, OrderFinalityVerifyErrorCodeV1,
        OrderStateExecutionBindingReceiptProofV1, VerifiedOrderFinalityV1,
        EXECUTION_BINDING_CLAIM_DOMAIN_V1, GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1,
        MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1, MAX_ORDER_FINALITY_PROOF_INPUT_BYTES_V1,
        MAX_TRUST_BUNDLE_INPUT_BYTES_V1, STATE_LEAF_DOMAIN, STATE_NODE_DOMAIN,
        STATE_TREE_SIBLING_COUNT_V1, STATE_TREE_VERSION_V1,
    };

    const TEST_BINDING_CANDIDATE_HEIGHT: u64 = 8;
    const TEST_BINDING_CANDIDATE_BLOCK_ID: [u8; 32] = [0x66; 32];

    fn corpus() -> Value {
        serde_json::from_str(include_str!(
            "../../../../docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json"
        ))
        .expect("checked-in corpus is JSON")
    }

    fn hex(raw: &str) -> Vec<u8> {
        assert_eq!(raw.len() % 2, 0);
        (0..raw.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).expect("fixture hex"))
            .collect()
    }

    fn fixtures() -> (Vec<u8>, Vec<u8>, Value) {
        let corpus = corpus();
        let trust = hex(corpus["trust_bundle_cev1_hex"].as_str().expect("trust hex"));
        let proof = hex(corpus["order_finality_proof_cev1_hex"]
            .as_str()
            .expect("proof hex"));
        (trust, proof, corpus)
    }

    fn direct_ordinary_fixtures() -> (Vec<u8>, Vec<u8>, Value) {
        let corpus = corpus();
        let direct = &corpus["direct_ordinary_target_case"];
        let trust = hex(direct["trust_bundle_cev1_hex"]
            .as_str()
            .expect("direct trust hex"));
        let proof = hex(direct["order_finality_proof_cev1_hex"]
            .as_str()
            .expect("direct proof hex"));
        (trust, proof, corpus)
    }

    fn application_value(object_kind: u16, object_id: [u8; 32]) -> Vec<u8> {
        let mut value = Vec::new();
        put_u16(&mut value, 1);
        put_u16(&mut value, object_kind);
        put_hash(&mut value, object_id);
        put_bytes(&mut value, b"immutable-task-object");
        put_bytes(&mut value, b"mutable-task-state");
        value
    }

    fn synthetic_order_with_state_root(state_root: [u8; 32]) -> VerifiedOrderFinalityV1 {
        let mut verified_ancestry = std::collections::BTreeMap::new();
        verified_ancestry.insert(
            TEST_BINDING_CANDIDATE_HEIGHT,
            TEST_BINDING_CANDIDATE_BLOCK_ID,
        );
        verified_ancestry.insert(9, [5; 32]);
        VerifiedOrderFinalityV1 {
            pinned_trust_sha256: [1; 32],
            proof_id: [2; 32],
            chain_id: "trnm-state-membership-test".to_owned(),
            genesis_hash: [3; 32],
            protocol_version: 1,
            stack_profile_hash: [4; 32],
            epoch: 0,
            finalized_height: 9,
            finalized_block_id: [5; 32],
            finalized_post_state_root: state_root,
            max_cev1_value_bytes: 64 * 1024,
            verified_ancestry,
        }
    }

    fn seal_execution_binding_claim(body: ExecutionBindingClaimBodyV1) -> ExecutionBindingClaimV1 {
        let claim_id = digest_value(EXECUTION_BINDING_CLAIM_DOMAIN_V1, &body);
        ExecutionBindingClaimV1 { body, claim_id }
    }

    fn encode_execution_binding_claim(claim: &ExecutionBindingClaimV1) -> Vec<u8> {
        let mut encoded = Vec::new();
        claim.encode(&mut encoded);
        encoded
    }

    fn execution_binding_fixture() -> (
        VerifiedOrderFinalityV1,
        ExecutionBindingClaimV1,
        [u8; 32],
        [u8; 32],
    ) {
        let candidate_composite_root = [0x91; 32];
        let final_execution_root = [0x92; 32];
        let candidate_height = TEST_BINDING_CANDIDATE_HEIGHT;
        let candidate_block_id = TEST_BINDING_CANDIDATE_BLOCK_ID;
        let object_kind = GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1;
        let material = derive_global_execution_binding_create_material_v1(
            "trnm-state-membership-test",
            [3; 32],
            1,
            [4; 32],
            candidate_height,
            candidate_block_id,
            candidate_composite_root,
            final_execution_root,
            candidate_height + 1,
        )
        .expect("binding material derives");
        let object_id = material.object_id();
        let value = material.value_bytes().to_vec();
        let siblings = (0..STATE_TREE_SIBLING_COUNT_V1)
            .map(|level| [u8::try_from(level % 251).expect("bounded level"); 32])
            .collect::<Vec<_>>();
        let witness = ExecutionBindingStateWitnessV1 {
            state_tree_version: STATE_TREE_VERSION_V1,
            object_kind,
            object_id,
            object_version: 0,
            value_bytes: value,
            siblings,
        };
        let (_, state_root) =
            application_state_membership_root_v1(&BoundedApplicationStateMembershipV1 {
                state_tree_version: witness.state_tree_version,
                object_kind: witness.object_kind,
                object_id: witness.object_id,
                object_version: witness.object_version,
                value_bytes: &witness.value_bytes,
                siblings: &witness.siblings,
            })
            .expect("fixture membership root");
        let order = synthetic_order_with_state_root(state_root);
        let claim = seal_execution_binding_claim(ExecutionBindingClaimBodyV1 {
            schema_version: 1,
            order_proof_id: order.proof_id(),
            chain_id: order.chain_id().to_owned(),
            genesis_hash: order.genesis_hash(),
            protocol_version: order.protocol_version(),
            stack_profile_hash: order.stack_profile_hash(),
            finalized_epoch: order.epoch(),
            finalized_block_id: order.finalized_block_id(),
            finalized_height: order.finalized_height(),
            finalized_post_state_root: order.finalized_post_state_root(),
            candidate_height,
            candidate_block_id,
            candidate_composite_root,
            final_execution_root,
            witnesses: vec![witness],
        });
        (order, claim, candidate_composite_root, final_execution_root)
    }

    fn opposite_orientation_root(
        witness: &ExecutionBindingStateWitnessV1,
        reversed_level: usize,
    ) -> [u8; 32] {
        let proof = BoundedApplicationStateMembershipV1 {
            state_tree_version: witness.state_tree_version,
            object_kind: witness.object_kind,
            object_id: witness.object_id,
            object_version: witness.object_version,
            value_bytes: &witness.value_bytes,
            siblings: &witness.siblings,
        };
        let (state_key, _) = application_state_membership_root_v1(&proof).expect("fixture root");
        let mut leaf = Vec::new();
        put_hash(&mut leaf, state_key);
        put_u16(&mut leaf, witness.object_kind);
        put_u64(&mut leaf, witness.object_version);
        put_bytes(&mut leaf, &witness.value_bytes);
        let mut running = digest(STATE_LEAF_DOMAIN, &leaf);
        for (level, sibling) in witness.siblings.iter().enumerate() {
            let bit_index = 255 - level;
            let byte = state_key[bit_index / 8];
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            let canonical_left = bit == 0;
            let running_left = if level == reversed_level {
                !canonical_left
            } else {
                canonical_left
            };
            let (left, right) = if running_left {
                (running, *sibling)
            } else {
                (*sibling, running)
            };
            let mut node = Vec::new();
            put_u16(&mut node, u16::try_from(level).expect("bounded level"));
            put_hash(&mut node, left);
            put_hash(&mut node, right);
            running = digest(STATE_NODE_DOMAIN, &node);
        }
        running
    }

    #[test]
    fn checked_in_fresh_genesis_proof_matches_independent_expected_ids() {
        let (trust, proof, corpus) = fixtures();
        let verified =
            verify_pinned_fresh_genesis_order_finality_v1(sha256(&trust), &trust, &proof)
                .expect("bounded checked-in proof verifies");
        let expected = &corpus["expected"];
        assert_eq!(
            verified.proof_id(),
            <[u8; 32]>::try_from(hex(expected["order_finality_proof_id"]
                .as_str()
                .expect("proof id")))
            .expect("proof id shape")
        );
        assert_eq!(verified.finalized_height(), 1);
        assert_eq!(
            verified.finalized_block_id(),
            <[u8; 32]>::try_from(hex(expected["finalized_block_id"]
                .as_str()
                .expect("block id")))
            .expect("block id shape")
        );
        assert_eq!(verified.protocol_version(), 1);
        assert_eq!(verified.epoch(), 0);
    }

    #[test]
    fn direct_ordinary_target_retains_only_certified_prefix_ancestry() {
        let (trust, proof, corpus) = direct_ordinary_fixtures();
        let verified = verify_pinned_direct_order_finality_v1(sha256(&trust), &trust, &proof)
            .expect("direct Ordinary target verifies");
        let expected = &corpus["direct_ordinary_target_case"]["expected"];
        assert_eq!(verified.finalized_height(), 2);
        assert_eq!(
            verified.finalized_block_id(),
            <[u8; 32]>::try_from(hex(expected["finalized_block_id"]
                .as_str()
                .expect("finalized id"),))
            .expect("Hash32"),
        );
        let genesis_id = <[u8; 32]>::try_from(hex(corpus["expected"]["trusted_genesis_block_id"]
            .as_str()
            .expect("genesis id")))
        .expect("Hash32");
        assert!(verified.proves_strict_ancestor_v1(1, genesis_id));
        assert!(!verified.proves_strict_ancestor_v1(1, [0x77; 32]));
        assert!(
            !verified.proves_strict_ancestor_v1(
                verified.finalized_height(),
                verified.finalized_block_id(),
            )
        );
        assert_eq!(
            verify_pinned_fresh_genesis_order_finality_v1(sha256(&trust), &trust, &proof,)
                .expect_err("FreshGenesis-only entry point rejects Ordinary target")
                .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidTarget,
        );
    }

    #[test]
    fn trust_pin_trailing_bytes_and_mutated_signature_fail_closed() {
        let (trust, proof, _) = fixtures();
        let wrong_pin = [0x55; 32];
        assert_eq!(
            verify_pinned_fresh_genesis_order_finality_v1(wrong_pin, &trust, &proof)
                .expect_err("wrong pin must reject")
                .code(),
            OrderFinalityVerifyErrorCodeV1::PinnedTrustMismatch
        );

        let mut trailing = proof.clone();
        trailing.push(0);
        assert_eq!(
            verify_pinned_fresh_genesis_order_finality_v1(sha256(&trust), &trust, &trailing,)
                .expect_err("trailing byte must reject")
                .code(),
            OrderFinalityVerifyErrorCodeV1::TrailingBytes
        );

        let mut corrupted = proof.clone();
        let signature_byte = corrupted
            .len()
            .checked_sub(128)
            .expect("fixture is sufficiently large");
        corrupted[signature_byte] ^= 1;
        assert!(
            verify_pinned_fresh_genesis_order_finality_v1(sha256(&trust), &trust, &corrupted,)
                .is_err()
        );
    }

    #[test]
    fn absolute_input_bounds_reject_before_trust_hash_or_decode() {
        let (trust, proof, _) = fixtures();
        let oversized_trust = vec![0x5a; MAX_TRUST_BUNDLE_INPUT_BYTES_V1 + 1];
        assert_eq!(
            verify_pinned_fresh_genesis_order_finality_v1([0x33; 32], &oversized_trust, &proof,)
                .expect_err("oversized trust must reject before its mismatched pin is hashed")
                .code(),
            OrderFinalityVerifyErrorCodeV1::ParserBound
        );

        let oversized_proof = vec![0x5a; MAX_ORDER_FINALITY_PROOF_INPUT_BYTES_V1 + 1];
        assert_eq!(
            verify_pinned_fresh_genesis_order_finality_v1(
                sha256(&trust),
                &trust,
                &oversized_proof,
            )
            .expect_err("oversized proof must reject before decoding")
            .code(),
            OrderFinalityVerifyErrorCodeV1::ParserBound
        );
    }

    #[test]
    fn committed_retained_view_bound_helper_rejects_three_chain_at_two() {
        assert_eq!(
            validate_retained_view_bound(3, 2)
                .expect_err("three-chain must not exceed committed retained views")
                .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidChain
        );
        validate_retained_view_bound(3, 3).expect("exact retained-view bound accepts");
    }

    #[test]
    fn exact_sparse_membership_binds_value_to_finalized_state_root() {
        let object_kind = 4;
        let object_id = [0x44; 32];
        let value = application_value(object_kind, object_id);
        let siblings = (0..STATE_TREE_SIBLING_COUNT_V1)
            .map(|level| [u8::try_from(level % 251).expect("bounded level"); 32])
            .collect::<Vec<_>>();
        let proof = BoundedApplicationStateMembershipV1 {
            state_tree_version: STATE_TREE_VERSION_V1,
            object_kind,
            object_id,
            object_version: 7,
            value_bytes: &value,
            siblings: &siblings,
        };
        let (expected_key, expected_root) =
            application_state_membership_root_v1(&proof).expect("root derives");
        let order = synthetic_order_with_state_root(expected_root);
        let verified = verify_bounded_application_state_membership_v1(&order, proof)
            .expect("exact membership verifies");
        assert_eq!(verified.order_proof_id(), order.proof_id());
        assert_eq!(verified.finalized_block_id(), order.finalized_block_id());
        assert_eq!(verified.finalized_height(), order.finalized_height());
        assert_eq!(verified.state_root(), order.finalized_post_state_root());
        assert_eq!(verified.state_key(), expected_key);
        assert_eq!(verified.object_kind(), object_kind);
        assert_eq!(verified.object_id(), object_id);
        assert_eq!(verified.object_version(), 7);
        assert_eq!(verified.value_bytes(), value);
    }

    #[test]
    fn sparse_membership_shape_value_and_root_substitutions_fail_closed() {
        let object_kind = 4;
        let object_id = [0x44; 32];
        let value = application_value(object_kind, object_id);
        let siblings = vec![[0x55; 32]; STATE_TREE_SIBLING_COUNT_V1];
        let proof = BoundedApplicationStateMembershipV1 {
            state_tree_version: STATE_TREE_VERSION_V1,
            object_kind,
            object_id,
            object_version: 7,
            value_bytes: &value,
            siblings: &siblings,
        };
        let (_, root) = application_state_membership_root_v1(&proof).expect("root derives");
        let order = synthetic_order_with_state_root(root);

        assert_eq!(
            verify_bounded_application_state_membership_v1(
                &order,
                BoundedApplicationStateMembershipV1 {
                    siblings: &siblings[..255],
                    ..proof
                },
            )
            .expect_err("short path rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidStateProof
        );

        let wrong_envelope = application_value(object_kind, [0x45; 32]);
        assert_eq!(
            verify_bounded_application_state_membership_v1(
                &order,
                BoundedApplicationStateMembershipV1 {
                    state_tree_version: STATE_TREE_VERSION_V1,
                    object_kind,
                    object_id,
                    object_version: 7,
                    value_bytes: &wrong_envelope,
                    siblings: &siblings,
                },
            )
            .expect_err("typed-object substitution rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidStateProof
        );

        let mut changed_siblings = siblings.clone();
        changed_siblings[128][0] ^= 1;
        assert_eq!(
            verify_bounded_application_state_membership_v1(
                &order,
                BoundedApplicationStateMembershipV1 {
                    state_tree_version: STATE_TREE_VERSION_V1,
                    object_kind,
                    object_id,
                    object_version: 7,
                    value_bytes: &value,
                    siblings: &changed_siblings,
                },
            )
            .expect_err("sibling substitution rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::StateRootMismatch
        );
    }

    #[test]
    fn tag50_create_material_is_deterministic_later_height_data_not_authority() {
        let exact = derive_global_execution_binding_create_material_v1(
            "trnm-state-membership-test",
            [3; 32],
            1,
            [4; 32],
            TEST_BINDING_CANDIDATE_HEIGHT,
            TEST_BINDING_CANDIDATE_BLOCK_ID,
            [0x91; 32],
            [0x92; 32],
            TEST_BINDING_CANDIDATE_HEIGHT + 1,
        )
        .expect("later-height material derives");
        let replay = derive_global_execution_binding_create_material_v1(
            "trnm-state-membership-test",
            [3; 32],
            1,
            [4; 32],
            TEST_BINDING_CANDIDATE_HEIGHT,
            TEST_BINDING_CANDIDATE_BLOCK_ID,
            [0x91; 32],
            [0x92; 32],
            TEST_BINDING_CANDIDATE_HEIGHT + 1,
        )
        .expect("exact replay derives identical inert bytes");
        assert_eq!(exact, replay);
        assert_eq!(exact.object_kind(), GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1);
        assert_eq!(exact.object_version(), 0);
        assert_ne!(exact.object_id(), [0; 32]);
        assert_ne!(exact.state_key(), [0; 32]);
        assert!(!exact.value_bytes().is_empty());

        let changed_root = derive_global_execution_binding_create_material_v1(
            "trnm-state-membership-test",
            [3; 32],
            1,
            [4; 32],
            TEST_BINDING_CANDIDATE_HEIGHT,
            TEST_BINDING_CANDIDATE_BLOCK_ID,
            [0x91; 32],
            [0x93; 32],
            TEST_BINDING_CANDIDATE_HEIGHT + 1,
        )
        .expect("another root tuple derives another key");
        assert_ne!(exact.object_id(), changed_root.object_id());
        assert_ne!(exact.state_key(), changed_root.state_key());
        assert_ne!(exact.value_bytes(), changed_root.value_bytes());

        assert_eq!(
            derive_global_execution_binding_create_material_v1(
                "trnm-state-membership-test",
                [3; 32],
                1,
                [4; 32],
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                [0x91; 32],
                [0x92; 32],
                TEST_BINDING_CANDIDATE_HEIGHT,
            )
            .expect_err("same-height materialization is self-referential")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        );
    }

    #[test]
    fn exact_registered_execution_binding_mints_nonforgeable_carrier() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();
        let verified = verify_order_state_execution_binding_claim_v1(
            &order,
            TEST_BINDING_CANDIDATE_HEIGHT,
            TEST_BINDING_CANDIDATE_BLOCK_ID,
            candidate_root,
            final_root,
            &encode_execution_binding_claim(&claim),
        )
        .expect("verified finality plus exact registered membership issues carrier");
        assert_eq!(verified.order_proof_id(), order.proof_id());
        assert_eq!(verified.candidate_height(), TEST_BINDING_CANDIDATE_HEIGHT);
        assert_eq!(
            verified.candidate_block_id(),
            TEST_BINDING_CANDIDATE_BLOCK_ID
        );
        assert_eq!(verified.candidate_composite_root(), candidate_root);
        assert_eq!(verified.final_execution_root(), final_root);
        assert_eq!(
            verified.binding_state_key(),
            application_state_membership_root_v1(&BoundedApplicationStateMembershipV1 {
                state_tree_version: claim.body.witnesses[0].state_tree_version,
                object_kind: claim.body.witnesses[0].object_kind,
                object_id: claim.body.witnesses[0].object_id,
                object_version: claim.body.witnesses[0].object_version,
                value_bytes: &claim.body.witnesses[0].value_bytes,
                siblings: &claim.body.witnesses[0].siblings,
            })
            .expect("fixture state key")
            .0,
        );
    }

    #[test]
    fn writer_receipt_typed_path_generates_exact_claim_and_issues_carrier() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();
        let witness = &claim.body.witnesses[0];
        let state_key =
            application_state_membership_root_v1(&BoundedApplicationStateMembershipV1 {
                state_tree_version: witness.state_tree_version,
                object_kind: witness.object_kind,
                object_id: witness.object_id,
                object_version: witness.object_version,
                value_bytes: &witness.value_bytes,
                siblings: &witness.siblings,
            })
            .expect("fixture receipt root")
            .0;
        let receipt = OrderStateExecutionBindingReceiptProofV1 {
            materialized_height: order.finalized_height(),
            materialized_state_root: order.finalized_post_state_root(),
            state_tree_version: witness.state_tree_version,
            object_kind: witness.object_kind,
            object_id: witness.object_id,
            object_version: witness.object_version,
            state_key,
            value_bytes: &witness.value_bytes,
            siblings: &witness.siblings,
        };
        assert_eq!(
            encode_order_state_execution_binding_claim_from_receipt_v1(&order, &receipt)
                .expect("typed receipt generates canonical claim"),
            encode_execution_binding_claim(&claim),
        );
        let verified = verify_order_state_execution_binding_receipt_v1(&order, receipt)
            .expect("typed receipt plus finality issues carrier");
        assert_eq!(verified.candidate_composite_root(), candidate_root);
        assert_eq!(verified.final_execution_root(), final_root);
        assert_eq!(verified.binding_state_key(), state_key);
    }

    #[test]
    fn writer_receipt_height_root_key_path_and_ancestry_mutants_fail_closed() {
        let (mut order, claim, _, _) = execution_binding_fixture();
        let witness = &claim.body.witnesses[0];
        let state_key =
            application_state_membership_root_v1(&BoundedApplicationStateMembershipV1 {
                state_tree_version: witness.state_tree_version,
                object_kind: witness.object_kind,
                object_id: witness.object_id,
                object_version: witness.object_version,
                value_bytes: &witness.value_bytes,
                siblings: &witness.siblings,
            })
            .unwrap()
            .0;
        let verify = |order: &VerifiedOrderFinalityV1,
                      height: u64,
                      root: [u8; 32],
                      key: [u8; 32],
                      siblings: &[[u8; 32]]| {
            verify_order_state_execution_binding_receipt_v1(
                order,
                OrderStateExecutionBindingReceiptProofV1 {
                    materialized_height: height,
                    materialized_state_root: root,
                    state_tree_version: witness.state_tree_version,
                    object_kind: witness.object_kind,
                    object_id: witness.object_id,
                    object_version: witness.object_version,
                    state_key: key,
                    value_bytes: &witness.value_bytes,
                    siblings,
                },
            )
        };
        assert_eq!(
            verify(
                &order,
                order.finalized_height() - 1,
                order.finalized_post_state_root(),
                state_key,
                &witness.siblings,
            )
            .expect_err("foreign materialized height rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        );
        let mut wrong_root = order.finalized_post_state_root();
        wrong_root[0] ^= 1;
        assert!(verify(
            &order,
            order.finalized_height(),
            wrong_root,
            state_key,
            &witness.siblings,
        )
        .is_err());
        let mut wrong_key = state_key;
        wrong_key[0] ^= 1;
        assert!(verify(
            &order,
            order.finalized_height(),
            order.finalized_post_state_root(),
            wrong_key,
            &witness.siblings,
        )
        .is_err());
        assert_eq!(
            verify(
                &order,
                order.finalized_height(),
                order.finalized_post_state_root(),
                state_key,
                &witness.siblings[..255],
            )
            .expect_err("short writer receipt path rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidStateProof,
        );
        order.verified_ancestry.clear();
        order
            .verified_ancestry
            .insert(order.finalized_height(), order.finalized_block_id());
        assert_eq!(
            verify(
                &order,
                order.finalized_height(),
                order.finalized_post_state_root(),
                state_key,
                &witness.siblings,
            )
            .expect_err("unproven candidate ancestry rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim,
        );
    }

    #[test]
    fn execution_binding_version_id_trailing_and_absolute_bound_mutants_fail_closed() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();

        let mut unknown_version = claim.clone();
        unknown_version.body.schema_version = 2;
        unknown_version = seal_execution_binding_claim(unknown_version.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&unknown_version),
            )
            .expect_err("unknown claim version rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::UnsupportedVariant
        );

        let mut wrong_id = claim.clone();
        wrong_id.claim_id[0] ^= 1;
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&wrong_id),
            )
            .expect_err("claim id substitution rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim
        );

        let mut trailing = encode_execution_binding_claim(&claim);
        trailing.push(0);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &trailing,
            )
            .expect_err("trailing claim byte rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::TrailingBytes
        );

        let oversized = vec![0x5a; MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1 + 1];
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &oversized,
            )
            .expect_err("absolute claim bound rejects before decode")
            .code(),
            OrderFinalityVerifyErrorCodeV1::ParserBound
        );
    }

    #[test]
    fn execution_binding_order_candidate_and_terminal_root_mutants_fail_closed() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();

        for mutation in 0..6 {
            let mut changed = claim.clone();
            match mutation {
                0 => changed.body.order_proof_id[0] ^= 1,
                1 => changed.body.finalized_post_state_root[0] ^= 1,
                2 => changed.body.candidate_height += 1,
                3 => changed.body.candidate_block_id[0] ^= 1,
                4 => changed.body.candidate_composite_root[0] ^= 1,
                5 => changed.body.final_execution_root[0] ^= 1,
                _ => unreachable!(),
            }
            let changed = seal_execution_binding_claim(changed.body);
            assert_eq!(
                verify_order_state_execution_binding_claim_v1(
                    &order,
                    TEST_BINDING_CANDIDATE_HEIGHT,
                    TEST_BINDING_CANDIDATE_BLOCK_ID,
                    candidate_root,
                    final_root,
                    &encode_execution_binding_claim(&changed),
                )
                .expect_err("Order/G2 substitution rejects")
                .code(),
                OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim
            );
        }
    }

    #[test]
    fn execution_binding_sparse_path_node_and_side_orientation_mutants_fail_closed() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();

        let mut short = claim.clone();
        short.body.witnesses[0].siblings.pop();
        let short = seal_execution_binding_claim(short.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&short),
            )
            .expect_err("255-node sparse path rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidStateProof
        );

        let mut long = claim.clone();
        long.body.witnesses[0].siblings.push([0xaa; 32]);
        let long = seal_execution_binding_claim(long.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&long),
            )
            .expect_err("257-node sparse path rejects before allocation")
            .code(),
            OrderFinalityVerifyErrorCodeV1::ParserBound
        );

        let mut changed_node = claim.clone();
        changed_node.body.witnesses[0].siblings[128][0] ^= 1;
        let changed_node = seal_execution_binding_claim(changed_node.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&changed_node),
            )
            .expect_err("sparse sibling substitution rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::StateRootMismatch
        );

        let reversed_root = opposite_orientation_root(&claim.body.witnesses[0], 73);
        let reversed_order = synthetic_order_with_state_root(reversed_root);
        let mut reversed = claim.clone();
        reversed.body.finalized_post_state_root = reversed_root;
        let reversed = seal_execution_binding_claim(reversed.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &reversed_order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&reversed),
            )
            .expect_err("opposite left/right sparse-node orientation rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::StateRootMismatch
        );
    }

    #[test]
    fn execution_binding_duplicate_unordered_and_unknown_object_keys_fail_closed() {
        let (order, claim, candidate_root, final_root) = execution_binding_fixture();

        let mut duplicate = claim.clone();
        duplicate
            .body
            .witnesses
            .push(duplicate.body.witnesses[0].clone());
        let duplicate = seal_execution_binding_claim(duplicate.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&duplicate),
            )
            .expect_err("duplicate typed state key rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim
        );

        let mut unordered = claim.clone();
        let mut earlier = unordered.body.witnesses[0].clone();
        earlier.object_kind = 3;
        earlier.object_id = [0x33; 32];
        earlier.value_bytes = application_value(earlier.object_kind, earlier.object_id);
        unordered.body.witnesses.push(earlier);
        let unordered = seal_execution_binding_claim(unordered.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&unordered),
            )
            .expect_err("non-increasing typed state keys reject")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim
        );

        let mut unknown = claim.clone();
        unknown.body.witnesses[0].object_kind = 51;
        unknown.body.witnesses[0].value_bytes = application_value(
            unknown.body.witnesses[0].object_kind,
            unknown.body.witnesses[0].object_id,
        );
        let unknown = seal_execution_binding_claim(unknown.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&unknown),
            )
            .expect_err("unregistered application ObjectKind rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidStateProof
        );

        let mut empty = claim;
        empty.body.witnesses.clear();
        let empty = seal_execution_binding_claim(empty.body);
        assert_eq!(
            verify_order_state_execution_binding_claim_v1(
                &order,
                TEST_BINDING_CANDIDATE_HEIGHT,
                TEST_BINDING_CANDIDATE_BLOCK_ID,
                candidate_root,
                final_root,
                &encode_execution_binding_claim(&empty),
            )
            .expect_err("empty witness bundle rejects")
            .code(),
            OrderFinalityVerifyErrorCodeV1::InvalidExecutionBindingClaim
        );
    }
}
