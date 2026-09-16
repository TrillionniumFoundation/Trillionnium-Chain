//! Native PoCO trust path. Peers supply bytes and target claims; an independently
//! pinned positive-height checkpoint supplies trust. The native epoch-zero case
//! is deliberately separate from the unchanged generic weak-subjectivity API.

use crate::{
    CheckpointLinkV0, Digest32V0, VerifiedTrustPathV0, WeakSubjectivityAnchorV0,
    MAX_TRUST_PATH_LINKS_V0,
};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use trnm_consensus_crypto::{
    decode_verify_epoch_first_finality_strict_v1, decode_verify_finality_proof_strict_v0,
    validate_validator_set_strict_ed25519_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact,
    decode_validator_set_v0_exact, BlockHeader, Cev0AdmissionBudgetV0, ConsensusParametersV0,
    DecodeError, EpochActivationEvidencePreimagesV0, ValidationError, ValidatorSet,
};

/// Local admission ceilings; these allocate no consensus wire identifiers.
pub const MAX_NATIVE_ANCHOR_BYTES_V1: usize = 4 * 1024 * 1024;
pub const MAX_NATIVE_TRUST_PATH_BYTES_V1: usize = 64 * 1024 * 1024;

/// Compute the exact configured anchor pin. Obtaining this digest from the same
/// peer that supplies the bytes establishes no trust. Operators must provision
/// it independently, including their checkpoint freshness policy.
pub fn native_trust_anchor_pin_v1(
    header: &[u8],
    set: &[u8],
    parameters: &[u8],
) -> Result<Digest32V0, NativeTrustErrorV1> {
    checked_size(&[header, set, parameters], MAX_NATIVE_ANCHOR_BYTES_V1)?;
    Ok(Digest32V0::hash(
        b"trnm.state-sync.native-anchor.v1",
        &[header, set, parameters],
    ))
}

#[derive(Debug)]
pub struct NativeTrustAnchorV1 {
    header: BlockHeader,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    pin: Digest32V0,
}

impl NativeTrustAnchorV1 {
    /// Admits an explicit trust root, not a peer-derived proof of this root.
    /// Canonical decoders reject trailing bytes; all keys receive strict checks.
    pub fn from_pinned_bytes(
        header: &[u8],
        set: &[u8],
        parameters: &[u8],
        independently_configured_pin: Digest32V0,
    ) -> Result<Self, NativeTrustErrorV1> {
        let pin = native_trust_anchor_pin_v1(header, set, parameters)?;
        if independently_configured_pin == Digest32V0([0; 32])
            || pin != independently_configured_pin
        {
            return Err(NativeTrustErrorV1::AnchorPinMismatch);
        }
        let header = decode_block_header_v0_exact(header).map_err(NativeTrustErrorV1::Decode)?;
        let set = decode_validator_set_v0_exact(set).map_err(NativeTrustErrorV1::Decode)?;
        let parameters =
            decode_consensus_parameters_v0_exact(parameters).map_err(NativeTrustErrorV1::Decode)?;
        set.validate_against_parameters(&parameters)
            .map_err(NativeTrustErrorV1::Consensus)?;
        validate_validator_set_strict_ed25519_v0(&set).map_err(NativeTrustErrorV1::Consensus)?;
        if header.height().get() == 0
            || header.state_root().as_bytes() == &[0; 32]
            || !matches_context(&header, &set, &parameters)
        {
            return Err(NativeTrustErrorV1::AnchorContextMismatch);
        }
        Ok(Self {
            header,
            set,
            parameters,
            pin,
        })
    }
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.set
    }
    pub fn parameters(&self) -> &ConsensusParametersV0 {
        &self.parameters
    }
    pub fn pin(&self) -> Digest32V0 {
        self.pin
    }
}

/// An untrusted step; `expected` is a checked target claim, never authority.
/// Ordinary proofs must extend the current header by one. Epoch steps carry
/// all eight evidence preimages and join the current application checkpoint
/// through its two old-epoch seal blocks to the first new block (height + 3).
#[derive(Clone, Copy)]
pub enum NativeTrustStepV1<'a> {
    Ordinary {
        proof: &'a [u8],
        expected: FinalityExpectationV0,
    },
    EpochFirst {
        evidence: EpochActivationEvidencePreimagesV0<'a>,
        proof: &'a [u8],
        expected: FinalityExpectationV0,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct NativeTrustPathLimitsV1 {
    pub maximum_links: usize,
    pub maximum_total_bytes: usize,
}
impl Default for NativeTrustPathLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_links: MAX_TRUST_PATH_LINKS_V0,
            maximum_total_bytes: MAX_NATIVE_TRUST_PATH_BYTES_V1,
        }
    }
}

/// Only successful strict signature, exact-parent and complete epoch evidence
/// verification can issue this result. The projection allows the existing
/// non-destructive snapshot session to consume the same authenticated target.
///
/// ```compile_fail
/// use trnm_state_sync_v0::VerifiedNativeTrustPathV1;
/// let forged = VerifiedNativeTrustPathV1 {};
/// ```
#[derive(Debug)]
pub struct VerifiedNativeTrustPathV1 {
    header: BlockHeader,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    projection: VerifiedTrustPathV0,
}
impl VerifiedNativeTrustPathV1 {
    pub fn terminal_header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn terminal_validator_set(&self) -> &ValidatorSet {
        &self.set
    }
    pub fn terminal_parameters(&self) -> &ConsensusParametersV0 {
        &self.parameters
    }
    pub fn snapshot_trust_path(&self) -> &VerifiedTrustPathV0 {
        &self.projection
    }
    pub fn into_snapshot_trust_path(self) -> VerifiedTrustPathV0 {
        self.projection
    }
}

#[derive(Debug)]
pub enum NativeTrustErrorV1 {
    Bounds,
    AnchorPinMismatch,
    AnchorContextMismatch,
    DisconnectedStep,
    Decode(DecodeError),
    Consensus(ValidationError),
    Finality(StrictFinalityErrorV0),
}
impl fmt::Display for NativeTrustErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounds => f.write_str("native trust path exceeds its admission bounds"),
            Self::AnchorPinMismatch => {
                f.write_str("native anchor does not match independently configured pin")
            }
            Self::AnchorContextMismatch => f.write_str("native anchor header/context mismatch"),
            Self::DisconnectedStep => {
                f.write_str("native proof does not extend the authenticated current head")
            }
            Self::Decode(e) => write!(f, "native canonical decoding: {e}"),
            Self::Consensus(e) => write!(f, "native context: {e}"),
            Self::Finality(e) => write!(f, "native strict finality: {e}"),
        }
    }
}
impl Error for NativeTrustErrorV1 {}

fn checked_size(parts: &[&[u8]], maximum: usize) -> Result<usize, NativeTrustErrorV1> {
    let size = parts
        .iter()
        .try_fold(0usize, |sum, bytes| {
            if bytes.is_empty() {
                None
            } else {
                sum.checked_add(bytes.len())
            }
        })
        .ok_or(NativeTrustErrorV1::Bounds)?;
    if size > maximum {
        return Err(NativeTrustErrorV1::Bounds);
    }
    Ok(size)
}
fn evidence_parts(e: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        e.old_checkpoint_finality,
        e.next_epoch_commitment,
        e.authorization_kernel,
        e.old_validator_set,
        e.old_consensus_parameters,
        e.new_validator_set,
        e.new_consensus_parameters,
        e.authenticated_checkpoint_parent_header,
    ]
}
fn step_digest(step: NativeTrustStepV1<'_>) -> Result<(usize, Digest32V0), NativeTrustErrorV1> {
    let mut parts = Vec::with_capacity(9);
    let domain: &[u8] = match step {
        NativeTrustStepV1::Ordinary { proof, .. } => {
            parts.push(proof);
            b"trnm.state-sync.native-ordinary-proof.v1"
        }
        NativeTrustStepV1::EpochFirst {
            evidence, proof, ..
        } => {
            parts.extend(evidence_parts(evidence));
            parts.push(proof);
            b"trnm.state-sync.native-epoch-proof.v1"
        }
    };
    let size = checked_size(&parts, MAX_NATIVE_TRUST_PATH_BYTES_V1)?;
    Ok((size, Digest32V0::hash(domain, &parts)))
}
fn matches_context(
    header: &BlockHeader,
    set: &ValidatorSet,
    params: &ConsensusParametersV0,
) -> bool {
    header.genesis_hash() == set.genesis_hash()
        && header.chain_id() == set.chain_id()
        && header.protocol_version() == set.protocol_version()
        && header.epoch() == set.epoch()
        && header.validator_set_id() == set.id()
        && header.consensus_parameters_hash() == params.hash()
}

/// All bytes/link counts are bounded before signature work. The caller supplies
/// one mutable CEV0 work budget across the complete path; failures never refund
/// work. No parser fallback, peer-selected trust set, clock freshness assertion,
/// application installation or signer activation is performed by this API.
pub fn verify_native_trust_path_v1(
    anchor: &NativeTrustAnchorV1,
    steps: &[NativeTrustStepV1<'_>],
    limits: NativeTrustPathLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTrustPathV1, NativeTrustErrorV1> {
    if steps.is_empty() || steps.len() > limits.maximum_links.min(MAX_TRUST_PATH_LINKS_V0) {
        return Err(NativeTrustErrorV1::Bounds);
    }
    let mut total = 0usize;
    let mut digests = Vec::with_capacity(steps.len());
    for step in steps {
        let (size, digest) = step_digest(*step)?;
        total = total.checked_add(size).ok_or(NativeTrustErrorV1::Bounds)?;
        if total
            > limits
                .maximum_total_bytes
                .min(MAX_NATIVE_TRUST_PATH_BYTES_V1)
        {
            return Err(NativeTrustErrorV1::Bounds);
        }
        digests.push(digest);
    }
    let chain = Digest32V0::hash(
        b"trnm.state-sync.native-chain.v1",
        &[
            anchor.header.genesis_hash().as_bytes(),
            anchor.header.chain_id().as_bytes(),
        ],
    );
    let protocol = Digest32V0::hash(
        b"trnm.state-sync.native-protocol.v1",
        &[&anchor.header.protocol_version().get().to_be_bytes()],
    );
    let projected_anchor = WeakSubjectivityAnchorV0 {
        chain_id: chain,
        protocol_digest: protocol,
        epoch: anchor.header.epoch().get(),
        height: anchor.header.height().get(),
        checkpoint_digest: anchor.pin,
        validator_set_digest: Digest32V0(*anchor.set.id().as_bytes()),
    };
    let mut header = anchor.header.clone();
    let mut set = anchor.set.clone();
    let mut parameters = anchor.parameters;
    let mut previous_digest = anchor.pin;
    let mut terminal = None;
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.state-sync.trust-path.v0");
    hasher.update(anchor.pin.0);
    for (step, digest) in steps.iter().zip(digests) {
        let old_set_id = set.id();
        let old_epoch = header.epoch();
        let old_height = header.height();
        match *step {
            NativeTrustStepV1::Ordinary { proof, expected } => {
                if expected.parent_id != header.id()
                    || expected.parent_height != header.height()
                    || expected.parent_timestamp_ms != header.timestamp_ms()
                    || old_height.get().checked_add(1) != Some(expected.height.get())
                {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                let verified = decode_verify_finality_proof_strict_v0(
                    POCO_THREE_CHAIN_PROOF_CLASS_V0,
                    proof,
                    &set,
                    &parameters,
                    expected,
                    budget,
                )
                .map_err(NativeTrustErrorV1::Finality)?;
                header = verified.proof().finalized_block().header().clone();
                if header.epoch() != old_epoch {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
            }
            NativeTrustStepV1::EpochFirst {
                evidence,
                proof,
                expected,
            } => {
                if old_height.get().checked_add(3) != Some(expected.height.get()) {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                let verified = decode_verify_epoch_first_finality_strict_v1(
                    evidence,
                    proof,
                    &set,
                    &parameters,
                    expected,
                    budget,
                )
                .map_err(NativeTrustErrorV1::Finality)?;
                if verified.checkpoint_header() != &header
                    || old_epoch.get().checked_add(1)
                        != Some(verified.new_validator_set().epoch().get())
                {
                    return Err(NativeTrustErrorV1::DisconnectedStep);
                }
                header = verified.proof().finalized_block().header().clone();
                set = verified.new_validator_set().clone();
                parameters = *verified.new_consensus_parameters();
            }
        }
        if !matches_context(&header, &set, &parameters)
            || header.genesis_hash() != anchor.header.genesis_hash()
            || header.chain_id() != anchor.header.chain_id()
            || header.protocol_version() != anchor.header.protocol_version()
            || header.state_root().as_bytes() == &[0; 32]
        {
            return Err(NativeTrustErrorV1::DisconnectedStep);
        }
        let mut link = CheckpointLinkV0 {
            chain_id: chain,
            protocol_digest: protocol,
            epoch: header.epoch().get(),
            height: header.height().get(),
            state_root: Digest32V0(*header.state_root().as_bytes()),
            validator_set_digest: Digest32V0(*old_set_id.as_bytes()),
            next_validator_set_digest: Digest32V0(*set.id().as_bytes()),
            parent_checkpoint_digest: previous_digest,
            finality_proof_digest: digest,
            checkpoint_digest: Digest32V0([0; 32]),
        };
        link.checkpoint_digest = link.canonical_digest();
        previous_digest = link.checkpoint_digest;
        hasher.update(link.checkpoint_digest.0);
        terminal = Some(link);
    }
    Ok(VerifiedNativeTrustPathV1 {
        header,
        set,
        parameters,
        projection: VerifiedTrustPathV0 {
            anchor: projected_anchor,
            terminal: terminal.ok_or(NativeTrustErrorV1::Bounds)?,
            link_count: steps.len() as u32,
            path_digest: Digest32V0(hasher.finalize().into()),
        },
    })
}

#[cfg(test)]
#[path = "native_trust_v1_tests.rs"]
mod tests;
