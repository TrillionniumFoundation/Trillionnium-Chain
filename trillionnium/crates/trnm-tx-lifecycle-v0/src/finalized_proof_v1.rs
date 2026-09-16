//! Native transaction/receipt membership in a strictly finalized frozen block.
//!
//! This verifies native bytes, not the separate M05 admission-envelope ID.
//! Existing native execution does not commit every M05 intent field. No API
//! here manufactures that missing binding, execution status or intermediate
//! state root, and no successful result advances the existing v0 lifecycle.

use crate::Digest32V0;
use std::{error::Error, fmt};
use trnm_consensus_crypto::{
    decode_verify_epoch_first_finality_strict_v1, decode_verify_finality_proof_strict_v0,
    FinalityExpectationV0, StrictFinalityErrorV0, POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_execution_receipt_commitment_v0_exact,
    ordered_leaf_digest_v0, BlockHeader, Cev0AdmissionBudgetV0, ConsensusParametersV0, DecodeError,
    EpochActivationEvidencePreimagesV0, ExecutionEventV0, ExecutionReceiptCommitmentV0,
    OrderedInclusionProofV0, RootKind, ValidationError, ValidatorSet,
};

pub const MAX_NATIVE_TX_PROOF_BYTES_V1: usize = 4 * 1024 * 1024;
pub const NATIVE_TX_PROOF_SCHEMA_V1: u16 = 1;

/// Public construction fields are untrusted data, never a verification token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTxProofPackageV1 {
    pub target_header: Vec<u8>,
    pub finality_proof: Vec<u8>,
    pub transaction: Vec<u8>,
    pub execution_receipt: Vec<u8>,
    pub index: u32,
    pub item_count: u32,
    pub payload_siblings: Vec<[u8; 32]>,
    pub receipt_siblings: Vec<[u8; 32]>,
}

/// Context must come from the consumer's authenticated genesis/checkpoint
/// history and local admission profile, never from the proof producer.
#[derive(Clone, Copy)]
pub struct NativeTxProofContextV1<'a> {
    pub trusted_validator_set: &'a ValidatorSet,
    pub trusted_parameters: &'a ConsensusParametersV0,
    pub expected: FinalityExpectationV0,
    pub maximum_transactions: u32,
    pub maximum_proof_bytes: usize,
}

/// Explicit epoch route. Old trust comes from authenticated local history;
/// evidence is untrusted and supplies the complete eight exact preimages.
/// The byte limit includes both this evidence and the transaction package.
#[derive(Clone, Copy)]
pub struct NativeTxEpochProofContextV1<'a> {
    pub trusted_old_validator_set: &'a ValidatorSet,
    pub trusted_old_parameters: &'a ConsensusParametersV0,
    pub evidence: EpochActivationEvidencePreimagesV0<'a>,
    pub expected: FinalityExpectationV0,
    pub maximum_transactions: u32,
    pub maximum_proof_bytes: usize,
}

/// Only this module's strict verifier can construct this result. A native
/// payload leaf authenticates bytes at an index; it is not an M05 tx_id.
///
/// ```compile_fail
/// use trnm_tx_lifecycle_v0::VerifiedNativeTxInclusionV1;
/// let forged = VerifiedNativeTxInclusionV1 {};
/// ```
#[derive(Debug)]
pub struct VerifiedNativeTxInclusionV1 {
    header: BlockHeader,
    receipt: ExecutionReceiptCommitmentV0,
    transaction: Vec<u8>,
    item_count: u32,
    proof_digest: Digest32V0,
}

impl VerifiedNativeTxInclusionV1 {
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn native_transaction_bytes(&self) -> &[u8] {
        &self.transaction
    }
    pub fn transaction_index(&self) -> u32 {
        self.receipt.transaction_index()
    }
    pub fn item_count(&self) -> u32 {
        self.item_count
    }
    pub fn payload_leaf_hash(&self) -> &[u8; 32] {
        self.receipt.payload_leaf_hash()
    }
    pub fn gas_used(&self) -> u64 {
        self.receipt.gas_used()
    }
    pub fn fee_charged(&self) -> u128 {
        self.receipt.fee_charged()
    }
    pub fn events(&self) -> &[ExecutionEventV0] {
        self.receipt.events()
    }
    pub fn proof_digest(&self) -> Digest32V0 {
        self.proof_digest
    }
}

#[derive(Debug)]
pub enum NativeTxProofErrorV1 {
    TooLarge,
    Truncated,
    UnsupportedSchema(u16),
    EmptyField,
    TrailingBytes,
    InvalidCount,
    InvalidBranch,
    ReceiptBindingMismatch,
    TargetMismatch,
    Decode(DecodeError),
    Commitment(ValidationError),
    Finality(StrictFinalityErrorV0),
}

impl fmt::Display for NativeTxProofErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("native transaction proof exceeds its admission budget"),
            Self::Truncated => f.write_str("native transaction proof is truncated"),
            Self::UnsupportedSchema(v) => {
                write!(f, "unsupported native transaction proof schema {v}")
            }
            Self::EmptyField => f.write_str("native transaction proof has an empty required field"),
            Self::TrailingBytes => f.write_str("native transaction proof has trailing bytes"),
            Self::InvalidCount => {
                f.write_str("native transaction proof index/count is outside the profile")
            }
            Self::InvalidBranch => f.write_str("native transaction proof has an invalid branch"),
            Self::ReceiptBindingMismatch => {
                f.write_str("native receipt does not bind the transaction/index")
            }
            Self::TargetMismatch => {
                f.write_str("native proof header is not the exact finalized target")
            }
            Self::Decode(e) => write!(f, "native proof canonical decode failed: {e}"),
            Self::Commitment(e) => write!(f, "native proof commitment failed: {e}"),
            Self::Finality(e) => write!(f, "native proof finality failed: {e}"),
        }
    }
}
impl Error for NativeTxProofErrorV1 {}

impl NativeTxProofPackageV1 {
    fn branches(
        &self,
    ) -> Result<(OrderedInclusionProofV0, OrderedInclusionProofV0), NativeTxProofErrorV1> {
        if self.payload_siblings.len() > 32 || self.receipt_siblings.len() > 32 {
            return Err(NativeTxProofErrorV1::InvalidBranch);
        }
        let payload = OrderedInclusionProofV0::new(
            RootKind::Payload,
            self.index,
            self.item_count,
            self.payload_siblings.clone(),
        )
        .map_err(|_| NativeTxProofErrorV1::InvalidBranch)?;
        let receipt = OrderedInclusionProofV0::new(
            RootKind::Receipts,
            self.index,
            self.item_count,
            self.receipt_siblings.clone(),
        )
        .map_err(|_| NativeTxProofErrorV1::InvalidBranch)?;
        Ok((payload, receipt))
    }

    /// Exact local envelope from M05's V1 proof contract. No consensus codec
    /// or signing preimage is changed by this transport framing.
    pub fn encode(&self) -> Result<Vec<u8>, NativeTxProofErrorV1> {
        self.branches()?;
        let fields = [
            &self.target_header,
            &self.finality_proof,
            &self.transaction,
            &self.execution_receipt,
        ];
        // Version, four Bytes lengths, index/count and two List lengths.
        let mut length = 2usize + 16 + 8 + 8;
        for field in fields {
            if field.is_empty() {
                return Err(NativeTxProofErrorV1::EmptyField);
            }
            length = length
                .checked_add(field.len())
                .ok_or(NativeTxProofErrorV1::TooLarge)?;
        }
        length = length
            .checked_add((self.payload_siblings.len() + self.receipt_siblings.len()) * 32)
            .ok_or(NativeTxProofErrorV1::TooLarge)?;
        if length > MAX_NATIVE_TX_PROOF_BYTES_V1 {
            return Err(NativeTxProofErrorV1::TooLarge);
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(&NATIVE_TX_PROOF_SCHEMA_V1.to_be_bytes());
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.item_count.to_be_bytes());
        for branch in [&self.payload_siblings, &self.receipt_siblings] {
            out.extend_from_slice(&(branch.len() as u32).to_be_bytes());
            for sibling in branch {
                out.extend_from_slice(sibling);
            }
        }
        Ok(out)
    }

    /// Decode transport structure only; this is not finality or membership.
    pub fn decode_exact(bytes: &[u8], maximum_bytes: usize) -> Result<Self, NativeTxProofErrorV1> {
        if bytes.len() > maximum_bytes.min(MAX_NATIVE_TX_PROOF_BYTES_V1) {
            return Err(NativeTxProofErrorV1::TooLarge);
        }
        let mut cursor = Cursor { bytes, offset: 0 };
        let version = u16::from_be_bytes(cursor.take(2)?.try_into().expect("two bytes"));
        if version != NATIVE_TX_PROOF_SCHEMA_V1 {
            return Err(NativeTxProofErrorV1::UnsupportedSchema(version));
        }
        let target_header = cursor.blob()?;
        let finality_proof = cursor.blob()?;
        let transaction = cursor.blob()?;
        let execution_receipt = cursor.blob()?;
        let index = cursor.u32()?;
        let item_count = cursor.u32()?;
        let payload_siblings = cursor.branch()?;
        let receipt_siblings = cursor.branch()?;
        if cursor.offset != bytes.len() {
            return Err(NativeTxProofErrorV1::TrailingBytes);
        }
        let value = Self {
            target_header,
            finality_proof,
            transaction,
            execution_receipt,
            index,
            item_count,
            payload_siblings,
            receipt_siblings,
        };
        value.branches()?;
        Ok(value)
    }
}

/// Strict Ed25519 finality plus both native ordered memberships. Same-epoch
/// ordinary/genesis proof support follows the strict finality API; unsupported
/// epoch-anchor classes fail closed, without trying a permissive decoder.
pub fn verify_native_tx_inclusion_v1(
    bytes: &[u8],
    context: NativeTxProofContextV1<'_>,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTxInclusionV1, NativeTxProofErrorV1> {
    budget
        .admit_root_bytes(bytes.len())
        .map_err(NativeTxProofErrorV1::Decode)?;
    let package = NativeTxProofPackageV1::decode_exact(bytes, context.maximum_proof_bytes)?;
    let header = decode_block_header_v0_exact(&package.target_header)
        .map_err(NativeTxProofErrorV1::Decode)?;
    let finality = decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        &package.finality_proof,
        context.trusted_validator_set,
        context.trusted_parameters,
        context.expected,
        budget,
    )
    .map_err(NativeTxProofErrorV1::Finality)?;
    if finality.proof().finalized_block().header() != &header {
        return Err(NativeTxProofErrorV1::TargetMismatch);
    }
    verify_memberships(
        package,
        header,
        context.trusted_parameters,
        context.maximum_transactions,
        Digest32V0::hash(b"trnm.tx.native-inclusion-proof.v1", &[bytes]),
    )
}

/// Complete strict epoch activation plus target membership, with no ordinary
/// decoder fallback. All receipt bounds use the authenticated *new* parameters.
/// This proves native bytes only and does not authorize signer activation.
pub fn verify_native_tx_epoch_inclusion_v1(
    bytes: &[u8],
    context: NativeTxEpochProofContextV1<'_>,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTxInclusionV1, NativeTxProofErrorV1> {
    let e = context.evidence;
    let parts = [
        e.old_checkpoint_finality,
        e.next_epoch_commitment,
        e.authorization_kernel,
        e.old_validator_set,
        e.old_consensus_parameters,
        e.new_validator_set,
        e.new_consensus_parameters,
        e.authenticated_checkpoint_parent_header,
        bytes,
    ];
    let total = parts
        .iter()
        .try_fold(0usize, |n, part| n.checked_add(part.len()))
        .ok_or(NativeTxProofErrorV1::TooLarge)?;
    if total
        > context
            .maximum_proof_bytes
            .min(MAX_NATIVE_TX_PROOF_BYTES_V1)
    {
        return Err(NativeTxProofErrorV1::TooLarge);
    }
    budget
        .admit_root_bytes(total)
        .map_err(NativeTxProofErrorV1::Decode)?;
    let package = NativeTxProofPackageV1::decode_exact(bytes, context.maximum_proof_bytes)?;
    let header = decode_block_header_v0_exact(&package.target_header)
        .map_err(NativeTxProofErrorV1::Decode)?;
    let finality = decode_verify_epoch_first_finality_strict_v1(
        e,
        &package.finality_proof,
        context.trusted_old_validator_set,
        context.trusted_old_parameters,
        context.expected,
        budget,
    )
    .map_err(NativeTxProofErrorV1::Finality)?;
    if finality.proof().finalized_block().header() != &header {
        return Err(NativeTxProofErrorV1::TargetMismatch);
    }
    verify_memberships(
        package,
        header,
        finality.new_consensus_parameters(),
        context.maximum_transactions,
        Digest32V0::hash(b"trnm.tx.native-epoch-inclusion-proof.v1", &parts),
    )
}

fn verify_memberships(
    package: NativeTxProofPackageV1,
    header: BlockHeader,
    parameters: &ConsensusParametersV0,
    maximum_transactions: u32,
    proof_digest: Digest32V0,
) -> Result<VerifiedNativeTxInclusionV1, NativeTxProofErrorV1> {
    // Every native logical transaction has at least a u32 Bytes prefix.
    if package.item_count > maximum_transactions.min(parameters.max_block_bytes() / 4) {
        return Err(NativeTxProofErrorV1::InvalidCount);
    }
    let receipt =
        decode_execution_receipt_commitment_v0_exact(&package.execution_receipt, parameters)
            .map_err(NativeTxProofErrorV1::Decode)?;
    let payload_leaf =
        ordered_leaf_digest_v0(RootKind::Payload, package.index, &package.transaction)
            .map_err(NativeTxProofErrorV1::Commitment)?;
    if receipt.transaction_index() != package.index || receipt.payload_leaf_hash() != &payload_leaf
    {
        return Err(NativeTxProofErrorV1::ReceiptBindingMismatch);
    }
    let (payload_branch, receipt_branch) = package.branches()?;
    payload_branch
        .verify(&package.transaction, header.payload_root().as_bytes())
        .map_err(NativeTxProofErrorV1::Commitment)?;
    receipt_branch
        .verify(
            &package.execution_receipt,
            header.receipts_root().as_bytes(),
        )
        .map_err(NativeTxProofErrorV1::Commitment)?;
    Ok(VerifiedNativeTxInclusionV1 {
        header,
        receipt,
        transaction: package.transaction,
        item_count: package.item_count,
        proof_digest,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], NativeTxProofErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NativeTxProofErrorV1::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NativeTxProofErrorV1::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, NativeTxProofErrorV1> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn blob(&mut self) -> Result<Vec<u8>, NativeTxProofErrorV1> {
        let length = self.u32()? as usize;
        if length == 0 {
            return Err(NativeTxProofErrorV1::EmptyField);
        }
        Ok(self.take(length)?.to_vec())
    }
    fn branch(&mut self) -> Result<Vec<[u8; 32]>, NativeTxProofErrorV1> {
        let count = self.u32()? as usize;
        if count > 32 {
            return Err(NativeTxProofErrorV1::InvalidBranch);
        }
        let bytes = self.take(count * 32)?;
        Ok(bytes
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().expect("32 bytes"))
            .collect())
    }
}

#[cfg(test)]
#[path = "finalized_proof_v1_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "finalized_proof_v1_epoch_tests.rs"]
mod epoch_tests;
