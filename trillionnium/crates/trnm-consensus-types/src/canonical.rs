use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{Result, SigningRoot, ValidationError};

pub(crate) const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";

pub(crate) const DOMAIN_BLOCK: &[u8] = b"trnm.poco-bft.block.v0";
pub(crate) const DOMAIN_PROPOSAL: &[u8] = b"trnm.poco-bft.proposal.v0";
pub(crate) const DOMAIN_VOTE: &[u8] = b"trnm.poco-bft.vote.v0";
pub(crate) const DOMAIN_TIMEOUT: &[u8] = b"trnm.poco-bft.timeout.v0";
pub(crate) const DOMAIN_QUORUM_CERTIFICATE: &[u8] = b"trnm.poco-bft.qc.v0";
pub(crate) const DOMAIN_TIMEOUT_CERTIFICATE: &[u8] = b"trnm.poco-bft.tc.v0";
pub(crate) const DOMAIN_HANDOFF_DESCRIPTOR: &[u8] = b"trnm.poco-bft.handoff-descriptor.v0";
pub(crate) const DOMAIN_HANDOFF_VOTE: &[u8] = b"trnm.poco-bft.handoff-vote.v0";
pub(crate) const DOMAIN_HANDOFF_CERTIFICATE: &[u8] = b"trnm.poco-bft.handoff-certificate.v0";
pub(crate) const DOMAIN_VALIDATOR_SET: &[u8] = b"trnm.poco-bft.validator-set.v0";
pub(crate) const DOMAIN_VALIDATOR_KEY_POP: &[u8] = b"trnm.poco-bft.validator-key-pop.v0";
pub(crate) const DOMAIN_PARAMETERS: &[u8] = b"trnm.poco-bft.parameters.v0";
pub(crate) const DOMAIN_EPOCH_COMMITMENT: &[u8] = b"trnm.poco-bft.epoch-commitment.v0";
pub(crate) const DOMAIN_UPGRADE_PLAN: &[u8] = b"trnm.poco-bft.upgrade-plan.v0";
pub(crate) const DOMAIN_FINALITY_PROOF: &[u8] = b"trnm.poco-bft.finality-proof.v0";
pub(crate) const DOMAIN_ORDERED_LEAF: &[u8] = b"trnm.poco-bft.ordered-leaf.v0";
pub(crate) const DOMAIN_ORDERED_NODE: &[u8] = b"trnm.poco-bft.ordered-node.v0";
pub(crate) const DOMAIN_ORDERED_ROOT: &[u8] = b"trnm.poco-bft.ordered-root.v0";
/// Non-protocol compatibility namespace for the prototype core's obsolete
/// six-digest `CommitProof`. It must never be accepted as FinalityProofV0.
pub(crate) const DOMAIN_OBSOLETE_COMMIT_PROOF_INTERNAL: &[u8] =
    b"trnm.internal.poco-bft.obsolete-commit-proof.v0";
pub(crate) const DOMAIN_DOUBLE_SIGN_EVIDENCE: &[u8] = b"trnm.poco-bft.double-sign-evidence.v0";
pub(crate) const DOMAIN_CONSUMPTION_CERTIFICATE: &[u8] = b"trnm.poco.consumption-certificate.v0";
pub(crate) const DOMAIN_CONSUMPTION_CERTIFICATE_ID: &[u8] =
    b"trnm.poco.consumption-certificate-id.v0";

#[allow(dead_code)]
pub(crate) const FROZEN_DOMAINS: [&[u8]; 21] = [
    DOMAIN_BLOCK,
    DOMAIN_PROPOSAL,
    DOMAIN_VOTE,
    DOMAIN_TIMEOUT,
    DOMAIN_QUORUM_CERTIFICATE,
    DOMAIN_TIMEOUT_CERTIFICATE,
    DOMAIN_HANDOFF_DESCRIPTOR,
    DOMAIN_HANDOFF_VOTE,
    DOMAIN_HANDOFF_CERTIFICATE,
    DOMAIN_VALIDATOR_SET,
    DOMAIN_VALIDATOR_KEY_POP,
    DOMAIN_PARAMETERS,
    DOMAIN_EPOCH_COMMITMENT,
    DOMAIN_UPGRADE_PLAN,
    DOMAIN_FINALITY_PROOF,
    DOMAIN_DOUBLE_SIGN_EVIDENCE,
    DOMAIN_ORDERED_LEAF,
    DOMAIN_ORDERED_NODE,
    DOMAIN_ORDERED_ROOT,
    DOMAIN_CONSUMPTION_CERTIFICATE,
    DOMAIN_CONSUMPTION_CERTIFICATE_ID,
];

pub trait CanonicalSignable {
    fn signing_root(&self) -> SigningRoot;
}

#[derive(Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
    error: Option<ValidationError>,
}

impl Encoder {
    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    #[allow(dead_code)]
    pub(crate) fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    #[allow(dead_code)]
    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        let Some(length) = self.checked_u32_len("Bytes", value.len()) else {
            return;
        };
        self.u32(length);
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn consensus_string(&mut self, value: &[u8]) {
        let Ok(length) = u16::try_from(value.len()) else {
            self.record_length_error("ConsensusString", value.len(), u16::MAX as usize);
            return;
        };
        self.u16(length);
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn list_len(&mut self, length: usize) {
        let Some(length) = self.checked_u32_len("List", length) else {
            return;
        };
        self.u32(length);
    }

    #[allow(dead_code)]
    pub(crate) fn optional(&mut self, present: bool, encode: impl FnOnce(&mut Self)) {
        self.u8(u8::from(present));
        if present {
            encode(self);
        }
    }

    pub(crate) fn optional_fixed(&mut self, value: Option<&[u8; 32]>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.fixed(value);
            }
            None => self.u8(0),
        }
    }

    pub(crate) fn into_bytes(self) -> Result<Vec<u8>> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.bytes),
        }
    }

    fn checked_u32_len(&mut self, field: &'static str, actual: usize) -> Option<u32> {
        match u32::try_from(actual) {
            Ok(length) => Some(length),
            Err(_) => {
                self.record_length_error(field, actual, u32::MAX as usize);
                None
            }
        }
    }

    fn record_length_error(&mut self, field: &'static str, actual: usize, maximum: usize) {
        if self.error.is_none() {
            self.error = Some(ValidationError::LengthOverflow {
                field,
                actual,
                maximum,
            });
        }
    }
}

pub(crate) fn try_canonical_bytes(encode: impl FnOnce(&mut Encoder)) -> Result<Vec<u8>> {
    let mut encoded = Encoder::default();
    encode(&mut encoded);
    encoded.into_bytes()
}

pub(crate) fn try_canonical_hash(
    domain: &[u8],
    encode: impl FnOnce(&mut Encoder),
) -> Result<[u8; 32]> {
    let encoded = try_canonical_bytes(encode)?;
    let prefix_length =
        u32::try_from(HASH_PREFIX.len()).map_err(|_| ValidationError::LengthOverflow {
            field: "hash prefix frame",
            actual: HASH_PREFIX.len(),
            maximum: u32::MAX as usize,
        })?;
    let domain_length =
        u32::try_from(domain.len()).map_err(|_| ValidationError::LengthOverflow {
            field: "domain frame",
            actual: domain.len(),
            maximum: u32::MAX as usize,
        })?;
    let encoded_length =
        u32::try_from(encoded.len()).map_err(|_| ValidationError::LengthOverflow {
            field: "CEV0 frame",
            actual: encoded.len(),
            maximum: u32::MAX as usize,
        })?;
    let mut hasher = Sha256::new();
    hasher.update(prefix_length.to_be_bytes());
    hasher.update(HASH_PREFIX);
    hasher.update(domain_length.to_be_bytes());
    hasher.update(domain);
    hasher.update(encoded_length.to_be_bytes());
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

/// Hashes a logical value whose constructor has already enforced every
/// variable-length bound. Consensus-facing constructors must perform those
/// checks before calling this helper.
pub(crate) fn canonical_hash(domain: &[u8], encode: impl FnOnce(&mut Encoder)) -> [u8; 32] {
    try_canonical_hash(domain, encode)
        .expect("bounded consensus value must fit the frozen CEV0 u32 frames")
}

pub(crate) fn signing_root(domain: &[u8], encode: impl FnOnce(&mut Encoder)) -> SigningRoot {
    SigningRoot::new(canonical_hash(domain, encode))
}
