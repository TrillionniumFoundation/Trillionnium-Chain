//! Typed boundary for handing an already-authorized Hepta artifact to the
//! chain adapter.
//!
//! This module deliberately does not own a trainer, artifact registry,
//! withdrawal journal, evaluator, or final-use token.  It only provides a
//! canonical, signed admission envelope that a chain adapter may submit after
//! the existing Hepta owners have produced and authorized the corresponding
//! receipt.  Chain reorganization may revoke a chain entitlement, but it must
//! never turn this envelope into permission to replay a local effect.

mod pq;
pub use pq::{
    PqHeptaAuthorityPinV2, PqHeptaAuthoritySetV2, PqHeptaHandoffError, SignedHeptaAdmissionV2,
    HEPTA_PQ_HANDOFF_VERSION, MAX_HEPTA_PQ_AUTHORITY_PINS, MAX_HEPTA_PQ_HANDOFF_BYTES,
};

use crate::canonical::{CanonicalCbor, CanonicalDecodeError, Decoder, Encoder, CANONICAL_ENCODING};
use crate::command::AuthorityRole;
use crate::state::AuthoritySetV1;
use crate::types::{Digest32, ExternalKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const HEPTA_HANDOFF_VERSION: u8 = 1;
pub const MAX_HANDOFF_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Includes all bounded identity strings, digests and a 64-byte signature.
/// Check this before parsing peer-controlled CBOR or allocating its strings.
pub const MAX_HANDOFF_ENVELOPE_BYTES: usize = 4096;

const ADMISSION_DOMAIN: &str = "trnm-hepta-artifact-admission-v1";
const SIGNATURE_DOMAIN: &str = "trnm-hepta-artifact-admission-signature-v1";

/// The digest-only facts returned by the existing Hepta artifact owner.
///
/// The chain never interprets the artifact bytes or creates a second registry.
/// Every digest is required to be non-zero so an omitted owner fact cannot be
/// represented as a successful admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeptaArtifactAdmissionV1 {
    pub operation_id: ExternalKey,
    pub artifact_digest: Digest32,
    /// Digest emitted by Hepta's WithdrawalBoundArtifactAdmissionV3.
    pub owner_admission_digest: Digest32,
    pub family_digest: Digest32,
    /// Identifies the source digest algorithm/domain mapping. The adapter must
    /// not reinterpret a Hepta digest as a chain digest without this profile.
    pub source_digest_profile_digest: Digest32,
    pub parent_artifact_digest: Option<Digest32>,
    pub generation: u64,
    pub withdrawal_scope_digest: Digest32,
    pub withdrawal_head_digest: Digest32,
    pub registry_head_digest: Digest32,
    pub evaluation_plan_digest: Digest32,
    pub task_scope_digest: Digest32,
    pub export_permission_digest: Digest32,
    pub payload_digest: Digest32,
    pub payload_len: u64,
    pub created_at_unix_s: u64,
    pub expires_at_unix_s: u64,
}

impl HeptaArtifactAdmissionV1 {
    pub fn validate(&self) -> Result<(), HeptaHandoffError> {
        self.operation_id
            .validate("operation_id")
            .map_err(|_| HeptaHandoffError::InvalidAdmission("operation_id"))?;
        for (field, digest) in [
            ("artifact_digest", &self.artifact_digest),
            ("owner_admission_digest", &self.owner_admission_digest),
            ("family_digest", &self.family_digest),
            (
                "source_digest_profile_digest",
                &self.source_digest_profile_digest,
            ),
            ("withdrawal_scope_digest", &self.withdrawal_scope_digest),
            ("withdrawal_head_digest", &self.withdrawal_head_digest),
            ("registry_head_digest", &self.registry_head_digest),
            ("evaluation_plan_digest", &self.evaluation_plan_digest),
            ("task_scope_digest", &self.task_scope_digest),
            ("export_permission_digest", &self.export_permission_digest),
            ("payload_digest", &self.payload_digest),
        ] {
            validate_digest(field, digest)?;
        }
        match (self.generation, self.parent_artifact_digest) {
            (0, _) => return Err(HeptaHandoffError::InvalidAdmission("generation")),
            (1, None) => {}
            (1, Some(_)) => {
                return Err(HeptaHandoffError::InvalidAdmission("generation_one_parent"))
            }
            (_, None) => {
                return Err(HeptaHandoffError::InvalidAdmission(
                    "missing_parent_artifact",
                ))
            }
            (_, Some(parent)) => validate_digest("parent_artifact_digest", &parent)?,
        }
        if self.payload_len == 0 || self.payload_len > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(HeptaHandoffError::InvalidAdmission("payload_len"));
        }
        if self.created_at_unix_s == 0
            || self.expires_at_unix_s == 0
            || self.created_at_unix_s > self.expires_at_unix_s
        {
            return Err(HeptaHandoffError::InvalidAdmission("created_at_unix_s"));
        }
        Ok(())
    }

    /// Revalidate the owner admission at the instant it is submitted or used.
    /// A valid signature alone does not make an expired withdrawal-bound
    /// admission current.
    pub fn validate_at(&self, now_unix_s: u64) -> Result<(), HeptaHandoffError> {
        self.validate()?;
        if now_unix_s < self.created_at_unix_s {
            return Err(HeptaHandoffError::AdmissionNotYetValid);
        }
        if now_unix_s > self.expires_at_unix_s {
            return Err(HeptaHandoffError::AdmissionExpired);
        }
        Ok(())
    }

    pub fn admission_digest(&self) -> [u8; 32] {
        crate::canonical_hash(ADMISSION_DOMAIN, &self.canonical_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalCbor::canonical_bytes(self)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CanonicalDecodeError> {
        decoder.array(18)?;
        let version = decoder.uint()?;
        if version != HEPTA_HANDOFF_VERSION as u64 {
            return Err(CanonicalDecodeError::UnsupportedVersion(version));
        }
        let operation_id = ExternalKey::from_bytes(decoder.bytes_exact()?);
        let artifact_digest = decoder.bytes_exact()?;
        let owner_admission_digest = decoder.bytes_exact()?;
        let family_digest = decoder.bytes_exact()?;
        let source_digest_profile_digest = decoder.bytes_exact()?;
        let parent_artifact_digest = decoder.option_digest()?;
        let generation = decoder.uint()?;
        let withdrawal_scope_digest = decoder.bytes_exact()?;
        let withdrawal_head_digest = decoder.bytes_exact()?;
        let registry_head_digest = decoder.bytes_exact()?;
        let evaluation_plan_digest = decoder.bytes_exact()?;
        let task_scope_digest = decoder.bytes_exact()?;
        let export_permission_digest = decoder.bytes_exact()?;
        let payload_digest = decoder.bytes_exact()?;
        let payload_len = decoder.uint()?;
        let created_at_unix_s = decoder.uint()?;
        let expires_at_unix_s = decoder.uint()?;
        Ok(Self {
            operation_id,
            artifact_digest,
            owner_admission_digest,
            family_digest,
            source_digest_profile_digest,
            parent_artifact_digest,
            generation,
            withdrawal_scope_digest,
            withdrawal_head_digest,
            registry_head_digest,
            evaluation_plan_digest,
            task_scope_digest,
            export_permission_digest,
            payload_digest,
            payload_len,
            created_at_unix_s,
            expires_at_unix_s,
        })
    }
}

impl CanonicalCbor for HeptaArtifactAdmissionV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) {
        encoder.array(18);
        encoder.uint(HEPTA_HANDOFF_VERSION as u64);
        self.operation_id.encode_canonical(encoder);
        encoder.bytes(&self.artifact_digest);
        encoder.bytes(&self.owner_admission_digest);
        encoder.bytes(&self.family_digest);
        encoder.bytes(&self.source_digest_profile_digest);
        match self.parent_artifact_digest {
            Some(digest) => encoder.bytes(&digest),
            None => encoder.null(),
        }
        encoder.uint(self.generation);
        encoder.bytes(&self.withdrawal_scope_digest);
        encoder.bytes(&self.withdrawal_head_digest);
        encoder.bytes(&self.registry_head_digest);
        encoder.bytes(&self.evaluation_plan_digest);
        encoder.bytes(&self.task_scope_digest);
        encoder.bytes(&self.export_permission_digest);
        encoder.bytes(&self.payload_digest);
        encoder.uint(self.payload_len);
        encoder.uint(self.created_at_unix_s);
        encoder.uint(self.expires_at_unix_s);
    }
}

/// An owner signature over the exact admission facts and chain namespace.
///
/// This is not a final-use token.  The chain adapter must still query the
/// current Hepta withdrawal head and local operation journal before any effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHeptaAdmissionV1 {
    pub chain_id: String,
    pub signer_did: String,
    pub public_key: [u8; 32],
    pub admission: HeptaArtifactAdmissionV1,
    pub signature: Vec<u8>,
}

impl SignedHeptaAdmissionV1 {
    pub fn sign(
        chain_id: String,
        signer_did: String,
        admission: HeptaArtifactAdmissionV1,
        signing_key: &SigningKey,
    ) -> Result<Self, HeptaHandoffError> {
        let mut signed = Self {
            chain_id,
            signer_did,
            public_key: signing_key.verifying_key().to_bytes(),
            admission,
            signature: Vec::new(),
        };
        signed.validate_unsigned()?;
        signed.signature = signing_key
            .sign(&signed.signing_bytes())
            .to_bytes()
            .to_vec();
        Ok(signed)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::default();
        encoder.array(7);
        encoder.text(SIGNATURE_DOMAIN);
        encoder.uint(HEPTA_HANDOFF_VERSION as u64);
        encoder.text(CANONICAL_ENCODING);
        encoder.text(&self.chain_id);
        encoder.text(&self.signer_did);
        encoder.bytes(&self.public_key);
        self.admission.encode_canonical(&mut encoder);
        encoder.finish()
    }

    pub fn verify_signature(&self) -> Result<(), HeptaHandoffError> {
        self.validate_unsigned()?;
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| HeptaHandoffError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| HeptaHandoffError::InvalidPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| HeptaHandoffError::InvalidSignature)
    }

    pub fn verify_with_authorities(
        &self,
        authorities: &AuthoritySetV1,
    ) -> Result<(), HeptaHandoffError> {
        self.verify_signature()?;
        if !authorities.authorizes_identity(
            AuthorityRole::HeptaAuthority,
            &self.signer_did,
            self.public_key,
        ) {
            return Err(HeptaHandoffError::UnauthorizedAuthority);
        }
        Ok(())
    }

    /// Validate a handoff against facts freshly supplied by the receiving
    /// Hepta owner and the destination selected by its operation journal.
    ///
    /// `expected` must come from those owners, never from the received envelope.
    /// Matching all fields binds task/export scope, parent/generation, current
    /// withdrawal and registry heads, payload and owner admission identity as
    /// one snapshot. Success is a comparison result and grants no final use or
    /// permission to replay an operation after a chain reorganization.
    pub fn verify_for_context(
        &self,
        authorities: &AuthoritySetV1,
        expected_chain_id: &str,
        expected: &HeptaArtifactAdmissionV1,
        now_unix_s: u64,
    ) -> Result<(), HeptaHandoffError> {
        expected.validate_at(now_unix_s)?;
        if self.chain_id != expected_chain_id {
            return Err(HeptaHandoffError::ContextMismatch("chain_id"));
        }
        if &self.admission != expected {
            return Err(HeptaHandoffError::ContextMismatch("owner_admission"));
        }
        self.verify_with_authorities_at(authorities, now_unix_s)
    }

    pub fn verify_with_authorities_at(
        &self,
        authorities: &AuthoritySetV1,
        now_unix_s: u64,
    ) -> Result<(), HeptaHandoffError> {
        self.admission.validate_at(now_unix_s)?;
        self.verify_with_authorities(authorities)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalCbor::canonical_bytes(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeptaHandoffError> {
        if bytes.len() > MAX_HANDOFF_ENVELOPE_BYTES {
            return Err(HeptaHandoffError::EnvelopeTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        decoder.array(7)?;
        let version = decoder.uint()?;
        if version != HEPTA_HANDOFF_VERSION as u64 {
            return Err(CanonicalDecodeError::UnsupportedVersion(version).into());
        }
        let encoding = decoder.text()?;
        if encoding != CANONICAL_ENCODING {
            return Err(HeptaHandoffError::EncodingMismatch(encoding));
        }
        let chain_id = decoder.text()?;
        let signer_did = decoder.text()?;
        let public_key = decoder.bytes_exact()?;
        let admission = HeptaArtifactAdmissionV1::decode(&mut decoder)?;
        let signature = decoder.bytes()?.to_vec();
        decoder.finish()?;
        let signed = Self {
            chain_id,
            signer_did,
            public_key,
            admission,
            signature,
        };
        if signed.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::NonCanonicalRoundTrip.into());
        }
        signed.verify_signature()?;
        Ok(signed)
    }

    fn validate_unsigned(&self) -> Result<(), HeptaHandoffError> {
        if self.chain_id.is_empty()
            || self.chain_id.len() > 64
            || !self.chain_id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(HeptaHandoffError::InvalidChainId);
        }
        if self.signer_did.len() < 5
            || self.signer_did.len() > 192
            || !self.signer_did.starts_with("did:")
            || !self.signer_did.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(HeptaHandoffError::InvalidSignerDid);
        }
        if self.public_key == [0; 32] {
            return Err(HeptaHandoffError::InvalidPublicKey);
        }
        self.admission.validate()
    }
}

impl CanonicalCbor for SignedHeptaAdmissionV1 {
    fn encode_canonical(&self, encoder: &mut Encoder) {
        encoder.array(7);
        encoder.uint(HEPTA_HANDOFF_VERSION as u64);
        encoder.text(CANONICAL_ENCODING);
        encoder.text(&self.chain_id);
        encoder.text(&self.signer_did);
        encoder.bytes(&self.public_key);
        self.admission.encode_canonical(encoder);
        encoder.bytes(&self.signature);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeptaHandoffError {
    #[error(transparent)]
    Canonical(#[from] CanonicalDecodeError),
    #[error("canonical encoding mismatch: {0}")]
    EncodingMismatch(String),
    #[error("invalid chain id")]
    InvalidChainId,
    #[error("invalid signer DID")]
    InvalidSignerDid,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unauthorized Hepta authority")]
    UnauthorizedAuthority,
    #[error("Hepta admission does not match current receiving context: {0}")]
    ContextMismatch(&'static str),
    #[error("Hepta admission envelope exceeds its byte limit")]
    EnvelopeTooLarge,
    #[error("invalid Hepta admission field: {0}")]
    InvalidAdmission(&'static str),
    #[error("Hepta admission is not yet valid")]
    AdmissionNotYetValid,
    #[error("Hepta admission has expired")]
    AdmissionExpired,
}

fn validate_digest(field: &'static str, digest: &Digest32) -> Result<(), HeptaHandoffError> {
    if *digest == [0; 32] {
        return Err(HeptaHandoffError::InvalidAdmission(field));
    }
    Ok(())
}
