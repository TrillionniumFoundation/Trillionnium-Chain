//! Candidate whole-payload model commitments, in the separate TCM2 namespace.
//!
//! TCM2 retains the complete V1 family and dependency-locator metadata, but
//! commits the actual complete payload through CCH1/SHA-512. The five old
//! dependency locators are aliases only: neither their inclusion nor the new
//! outer commitment upgrades the referenced dependencies. Each dependency still
//! needs its own full-content verification and independently trusted authority.
//! TCC2 (`CellContentClosureV2`) adds actual complete commitments/readback for
//! all five named dependency slots; a TCM2 readback alone does not cover them.
//!
//! The manifest is itself observed under ModelManifest, separately from the
//! payload's ModelPayload domain. Readback requires a caller-pinned *complete*
//! manifest claim, never a short ID received alongside the content. No returned
//! value authorizes installation, CURRENT, FinalUse, or production activation.
//! This module does not change the TCM1 chunk/transport/cache formats, implement
//! a Merkle tree, authenticate provenance, or freeze a mutable source file.

use std::{fmt, io::Read};

use trnm_protocol::content_commitment::{
    observe_bytes, observe_reader, ContentClaimV1, ContentCommitmentError, ContentContextV1,
    ContentKind, ContentReadBudget, ObservedContentV1, CONTENT_CLAIM_BYTES,
};

use super::{CellContextV1, CellErrorV1, MAX_CELL_BYTES};

mod closure;
pub use closure::{
    CellContentClosureReadbackV2, CellContentClosureV2, CellContentDependencyV2,
    CELL_CONTENT_DEPENDENCY_COUNT_V2, MAX_CELL_CONTENT_CLOSURE_BYTES_V2,
};

const MAGIC: &[u8; 4] = b"TCM2";
const LEGACY_ALIAS_COUNT: usize = 5;
const LEGACY_ALIAS_BYTES: usize = LEGACY_ALIAS_COUNT * 32;
const FIXED_BYTES: usize = 4 + 1 + LEGACY_ALIAS_BYTES + CONTENT_CLAIM_BYTES;
pub const MAX_CELL_CONTENT_MANIFEST_BYTES_V2: usize = FIXED_BYTES + 64;

/// A candidate content-format error, with read failures preserved as causes.
#[derive(Debug)]
pub enum CellContentErrorV2 {
    Invalid(&'static str),
    Metadata(CellErrorV1),
    Commitment(ContentCommitmentError),
}

impl fmt::Display for CellContentErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "cell content v2 rejected: {reason}"),
            Self::Metadata(error) => write!(f, "cell content v2 metadata: {error}"),
            Self::Commitment(error) => write!(f, "cell content v2: {error}"),
        }
    }
}

impl std::error::Error for CellContentErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Metadata(error) => Some(error),
            Self::Commitment(error) => Some(error),
        }
    }
}

impl From<ContentCommitmentError> for CellContentErrorV2 {
    fn from(error: ContentCommitmentError) -> Self {
        Self::Commitment(error)
    }
}

/// Canonical TCM2 metadata and a *claimed* complete payload commitment.
///
/// Decoding establishes only a well-formed declaration. The payload claim is
/// checked against a fresh, complete read by `verify_payload_reader`. To create
/// a declaration locally, `from_observed_payload` requires an actual complete
/// observation; there is no constructor from a legacy digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellContentManifestV2 {
    legacy_metadata: CellContextV1,
    payload: ContentClaimV1,
}

impl CellContentManifestV2 {
    pub fn from_observed_payload(
        legacy_metadata: CellContextV1,
        payload: &ObservedContentV1,
    ) -> Result<Self, CellContentErrorV2> {
        let value = Self {
            legacy_metadata,
            payload: payload.claim().clone(),
        };
        value.validate()?;
        Ok(value)
    }

    /// The original family and five locator aliases, not dependency authority.
    pub fn legacy_metadata(&self) -> &CellContextV1 {
        &self.legacy_metadata
    }

    pub fn payload_claim(&self) -> &ContentClaimV1 {
        &self.payload
    }

    pub fn validate(&self) -> Result<(), CellContentErrorV2> {
        self.legacy_metadata
            .validate()
            .map_err(CellContentErrorV2::Metadata)?;
        require(
            self.payload.context().kind() == ContentKind::ModelPayload,
            "payload purpose",
        )?;
        require(
            (1..=MAX_CELL_BYTES).contains(&self.payload.content_len()),
            "payload size",
        )
    }

    /// Exact wire: TCM2, U8 family length, ASCII family, five 32-byte legacy
    /// aliases (base/parent/tokenizer/layout/runtime), one 213-byte CCH1 payload
    /// claim. Length and all context fields live inside that full claim.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_BYTES + self.legacy_metadata.family.len());
        out.extend_from_slice(MAGIC);
        out.push(self.legacy_metadata.family.len() as u8);
        out.extend_from_slice(self.legacy_metadata.family.as_bytes());
        for alias in [
            self.legacy_metadata.base,
            self.legacy_metadata.parent,
            self.legacy_metadata.tokenizer,
            self.legacy_metadata.layout,
            self.legacy_metadata.runtime,
        ] {
            out.extend_from_slice(&alias);
        }
        out.extend_from_slice(&self.payload.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CellContentErrorV2> {
        require(
            (FIXED_BYTES + 1..=MAX_CELL_CONTENT_MANIFEST_BYTES_V2).contains(&bytes.len()),
            "manifest length",
        )?;
        require(&bytes[..4] == MAGIC, "manifest version")?;
        let family_len = usize::from(bytes[4]);
        require((1..=64).contains(&family_len), "family length")?;
        require(
            bytes.len() == FIXED_BYTES + family_len,
            "manifest exact coverage",
        )?;
        let family_end = 5 + family_len;
        let family = std::str::from_utf8(&bytes[5..family_end])
            .map_err(|_| CellContentErrorV2::Invalid("family encoding"))?
            .to_owned();
        let mut aliases = [[0u8; 32]; LEGACY_ALIAS_COUNT];
        for (index, alias) in aliases.iter_mut().enumerate() {
            let start = family_end + index * 32;
            alias.copy_from_slice(&bytes[start..start + 32]);
        }
        let [base, parent, tokenizer, layout, runtime] = aliases;
        let payload = ContentClaimV1::decode(&bytes[family_end + LEGACY_ALIAS_BYTES..])?;
        let value = Self {
            legacy_metadata: CellContextV1 {
                family,
                base,
                parent,
                tokenizer,
                layout,
                runtime,
            },
            payload,
        };
        value.validate()?;
        require(value.encode() == bytes, "canonical manifest encoding")?;
        Ok(value)
    }

    /// Observe these complete canonical manifest bytes under the independently
    /// selected manifest context. This does not re-read the declared payload.
    pub fn observe_manifest(
        &self,
        context: &ContentContextV1,
        budget: &mut ContentReadBudget,
    ) -> Result<ObservedContentV1, CellContentErrorV2> {
        self.validate()?;
        self.check_manifest_context(context)?;
        Ok(observe_bytes(context, budget, &self.encode())?)
    }

    /// Verify an independently pinned complete manifest claim, then read and
    /// verify every payload byte plus EOF. The pin must come from the caller's
    /// trusted owner; a claim carried by the same untrusted input is no pin.
    ///
    /// Short data, any I/O error, an extra byte, a different payload, or any
    /// profile/instance/generation mismatch refuses the entire readback. The
    /// common budget charges both reads, including their EOF probes, and is not
    /// refunded on failure. The owner supplies cancellation and time limits.
    pub fn verify_payload_reader<R: Read + ?Sized>(
        &self,
        expected_manifest: &ContentClaimV1,
        budget: &mut ContentReadBudget,
        reader: &mut R,
    ) -> Result<CellContentReadbackV2, CellContentErrorV2> {
        let manifest = self.observe_manifest(expected_manifest.context(), budget)?;
        expected_manifest.verify(&manifest)?;
        let payload = observe_reader(
            self.payload.context(),
            budget,
            self.payload.content_len(),
            reader,
        )?;
        self.payload.verify(&payload)?;
        Ok(CellContentReadbackV2 { manifest, payload })
    }

    pub fn verify_payload_bytes(
        &self,
        expected_manifest: &ContentClaimV1,
        budget: &mut ContentReadBudget,
        bytes: &[u8],
    ) -> Result<CellContentReadbackV2, CellContentErrorV2> {
        self.verify_payload_reader(expected_manifest, budget, &mut std::io::Cursor::new(bytes))
    }

    fn check_manifest_context(&self, context: &ContentContextV1) -> Result<(), CellContentErrorV2> {
        require(
            context.kind() == ContentKind::ModelManifest,
            "manifest purpose",
        )?;
        let payload_context = self.payload.context();
        require(
            context.profile_id() == payload_context.profile_id()
                && context.instance() == payload_context.instance()
                && context.generation() == payload_context.generation(),
            "manifest/payload context",
        )
    }
}

/// Two complete reads matched the pinned manifest and its payload claim. This
/// value has no deserializer or public constructor and is not an authorization
/// token, fresh custody attestation, or evidence that the payload is executable.
#[derive(Debug)]
pub struct CellContentReadbackV2 {
    manifest: ObservedContentV1,
    payload: ObservedContentV1,
}

impl CellContentReadbackV2 {
    pub fn manifest_observation(&self) -> &ObservedContentV1 {
        &self.manifest
    }

    pub fn payload_observation(&self) -> &ObservedContentV1 {
        &self.payload
    }

    pub fn manifest_claim(&self) -> &ContentClaimV1 {
        self.manifest.claim()
    }

    pub fn payload_claim(&self) -> &ContentClaimV1 {
        self.payload.claim()
    }
}

fn require(condition: bool, reason: &'static str) -> Result<(), CellContentErrorV2> {
    if condition {
        Ok(())
    } else {
        Err(CellContentErrorV2::Invalid(reason))
    }
}

#[cfg(test)]
mod tests;
