//! CPQ1 mathematical signatures joined to a complete full-content observation.
//! The expected claim and envelope are owner-pinned inputs. No returned value
//! is a live authorization, trusted migration source, CURRENT, or FinalUse.

use crate::pq_profile_auth::{
    CandidateProfileVerifier, CandidateSignatureObservation, ProfileAuthenticationError,
};
use trnm_protocol::{
    content_commitment::{ContentClaimV1, ContentKind, ObservedContentV1},
    crypto_profile::{CandidateEnvelope, CandidateVerificationBudget, CryptoPurpose},
};

#[derive(Debug)]
pub enum ContentAuthenticationError {
    Signature(ProfileAuthenticationError),
    Binding,
}
impl std::fmt::Display for ContentAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature(error) => error.fmt(f),
            Self::Binding => write!(f, "candidate content/envelope binding rejected"),
        }
    }
}
impl std::error::Error for ContentAuthenticationError {}

/// Evidence of this read and this signature check only. Owner freshness and
/// irreversible consumption must be checked separately at the actual effect.
pub struct CandidateContentSignatureObservation<'a> {
    signature: CandidateSignatureObservation<'a>,
    claim: ContentClaimV1,
}
impl<'a> CandidateContentSignatureObservation<'a> {
    pub fn signature(&self) -> &CandidateSignatureObservation<'a> {
        &self.signature
    }
    pub fn claim(&self) -> &ContentClaimV1 {
        &self.claim
    }
}

fn purpose_matches(kind: ContentKind, purpose: CryptoPurpose) -> bool {
    matches!(
        (kind, purpose),
        (ContentKind::StateSnapshot, CryptoPurpose::Recovery)
            | (ContentKind::MigrationCheckpoint, CryptoPurpose::Migration)
            | (
                ContentKind::ReleaseArtifact
                    | ContentKind::ModelManifest
                    | ContentKind::ModelPayload,
                CryptoPurpose::Release
            )
    )
}

/// Verify the complete CCH1 record as the CPQ1 signed payload. A raw digest,
/// legacy alias, another purpose or generation cannot stand in for the record.
/// Invalid joins consume the same signature reservation as other failed inputs.
pub fn verify_candidate_content<'a>(
    verifier: &CandidateProfileVerifier,
    budget: &mut CandidateVerificationBudget,
    wire: &'a [u8],
    expected: &CandidateEnvelope<'_>,
    expected_claim: &ContentClaimV1,
    observed: &ObservedContentV1,
) -> Result<CandidateContentSignatureObservation<'a>, ContentAuthenticationError> {
    let context = expected_claim.context();
    let binding_ok = context.profile_id() == verifier.profile().id()
        && context.generation() == expected.owner_generation
        && purpose_matches(context.kind(), expected.purpose)
        && expected.payload == expected_claim.encode();
    if !binding_ok || expected_claim.verify(observed).is_err() {
        budget
            .reserve(wire.len(), verifier.signer_ids().len())
            .map_err(|error| {
                ContentAuthenticationError::Signature(ProfileAuthenticationError::Policy(error))
            })?;
        return Err(ContentAuthenticationError::Binding);
    }
    let signature = verifier
        .verify(budget, wire, expected)
        .map_err(ContentAuthenticationError::Signature)?;
    Ok(CandidateContentSignatureObservation {
        signature,
        claim: expected_claim.clone(),
    })
}

#[cfg(test)]
mod profile_boundary_tests;
#[cfg(test)]
mod tests;
