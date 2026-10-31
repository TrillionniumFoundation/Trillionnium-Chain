//! Research-only, PQ-only Hepta admission envelope. This is a *separate*
//! versioned wire and trust root; V1 Ed25519 cannot satisfy its verifier.
//!
//! The hosting adapter supplies an independently pinned, current ML-DSA-65
//! authority set and a fresh Hepta owner snapshot. The wire may neither select
//! its own key nor authorize FinalUse, an install, replay or chain recovery.
//! This does not migrate the research state machine's classic authority set.

use super::{Decoder, HeptaArtifactAdmissionV1, HeptaHandoffError};
use thiserror::Error;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES,
};

pub const HEPTA_PQ_HANDOFF_VERSION: u8 = 2;
pub const MAX_HEPTA_PQ_HANDOFF_BYTES: usize = 8192;
pub const MAX_HEPTA_PQ_AUTHORITY_PINS: usize = 64;
const WIRE_MAGIC: &[u8; 4] = b"THP2";
const ALGORITHM: u8 = 0x65;
const SIGN_DOMAIN: &[u8] = b"TRNM/Hepta/ArtifactAdmission/ML-DSA-65/v2\0";

/// A trusted, externally provisioned binding for exactly one Hepta authority.
/// Key generations are *signer* generations, not artifact generations. A new
/// roster is an owner decision; these bytes may not be sourced from a packet.
#[derive(Clone, Debug)]
pub struct PqHeptaAuthorityPinV2 {
    pub signer_did: String,
    pub key_id: [u8; 32],
    pub generation: u64,
    pub spki: [u8; ML_DSA_65_SPKI_BYTES],
    pub not_before_unix_s: u64,
    pub expires_at_unix_s: u64,
    pub revoked_at_unix_s: Option<u64>,
}

impl PqHeptaAuthorityPinV2 {
    fn validate(&self) -> Result<PqNativeVerifier, PqHeptaHandoffError> {
        if !valid_did(&self.signer_did)
            || self.generation == 0
            || self.not_before_unix_s >= self.expires_at_unix_s
            || self.key_id == [0; 32]
            || ml_dsa_65_key_id_from_spki(&self.spki).ok() != Some(self.key_id)
        {
            return Err(PqHeptaHandoffError::InvalidPin);
        }
        PqNativeVerifier::from_pinned_spki(&self.spki, self.key_id)
            .map_err(|_| PqHeptaHandoffError::InvalidPin)
    }

    fn live_at(&self, now: u64) -> Result<(), PqHeptaHandoffError> {
        if now < self.not_before_unix_s
            || now >= self.expires_at_unix_s
            || self.revoked_at_unix_s.is_some_and(|at| now >= at)
        {
            return Err(PqHeptaHandoffError::RevokedOrExpired);
        }
        Ok(())
    }
}

/// Bounded in-memory roster. It intentionally has no fallback to
/// AuthoritySetV1, no automatic key rotation and no Deserialize from peer wire.
pub struct PqHeptaAuthoritySetV2 {
    entries: Vec<(PqHeptaAuthorityPinV2, PqNativeVerifier)>,
}

impl PqHeptaAuthoritySetV2 {
    pub fn new(mut pins: Vec<PqHeptaAuthorityPinV2>) -> Result<Self, PqHeptaHandoffError> {
        if pins.is_empty() || pins.len() > MAX_HEPTA_PQ_AUTHORITY_PINS {
            return Err(PqHeptaHandoffError::InvalidPin);
        }
        pins.sort_by(|a, b| a.signer_did.cmp(&b.signer_did));
        let mut entries = Vec::with_capacity(pins.len());
        for pin in pins {
            if entries
                .last()
                .is_some_and(|(previous, _): &(PqHeptaAuthorityPinV2, PqNativeVerifier)| {
                    previous.signer_did == pin.signer_did
                })
            {
                // Exactly one current generation per DID. Older generations
                // cannot be made valid by including both keys in the roster.
                return Err(PqHeptaHandoffError::InvalidPin);
            }
            let verifier = pin.validate()?;
            entries.push((pin, verifier));
        }
        Ok(Self { entries })
    }

    fn authorized<'a>(
        &'a self,
        signed: &SignedHeptaAdmissionV2,
        now: u64,
    ) -> Result<&'a PqNativeVerifier, PqHeptaHandoffError> {
        let index = self
            .entries
            .binary_search_by(|(pin, _)| pin.signer_did.cmp(&signed.signer_did))
            .map_err(|_| PqHeptaHandoffError::UnauthorizedAuthority)?;
        let (pin, verifier) = &self.entries[index];
        if signed.signer_key_id != pin.key_id || signed.signer_generation != pin.generation {
            return Err(PqHeptaHandoffError::UnauthorizedAuthority);
        }
        pin.live_at(now)?;
        Ok(verifier)
    }
}

/// An *untrusted* envelope until verify_for_context succeeds. In particular,
/// decode_untrusted does not create a verified key, authority or FinalUse token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeptaAdmissionV2 {
    pub chain_id: String,
    pub signer_did: String,
    pub signer_key_id: [u8; 32],
    pub signer_generation: u64,
    pub admission: HeptaArtifactAdmissionV1,
    pub signature: Vec<u8>,
}

impl SignedHeptaAdmissionV2 {
    pub fn sign(
        chain_id: String,
        signer_did: String,
        signer_generation: u64,
        admission: HeptaArtifactAdmissionV1,
        signer: &PqNativeSigningKey,
    ) -> Result<Self, PqHeptaHandoffError> {
        let mut signed = Self {
            chain_id,
            signer_did,
            signer_key_id: signer.public_key_id(),
            signer_generation,
            admission,
            signature: Vec::new(),
        };
        let message = signed.signing_message()?;
        signed.signature = signer
            .sign_exact_message(&message)
            .map_err(|_| PqHeptaHandoffError::InvalidSignature)?
            .to_vec();
        Ok(signed)
    }

    /// Verify against current externally pinned authorities and *current*
    /// expected owner facts. No classic-signature OR branch exists.
    pub fn verify_for_context(
        &self,
        pins: &PqHeptaAuthoritySetV2,
        expected_chain_id: &str,
        expected_admission: &HeptaArtifactAdmissionV1,
        now_unix_s: u64,
    ) -> Result<(), PqHeptaHandoffError> {
        self.validate_unsigned()?;
        expected_admission.validate_at(now_unix_s)?;
        if self.chain_id != expected_chain_id {
            return Err(PqHeptaHandoffError::ContextMismatch("chain_id"));
        }
        if self.admission != *expected_admission {
            return Err(PqHeptaHandoffError::ContextMismatch("owner_admission"));
        }
        self.admission.validate_at(now_unix_s)?;
        let verifier = pins.authorized(self, now_unix_s)?;
        if self.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqHeptaHandoffError::InvalidSignature);
        }
        verifier
            .verify_exact_message(&self.signing_message()?, &self.signature)
            .map_err(|_| PqHeptaHandoffError::InvalidSignature)?;
        Ok(())
    }

    fn validate_unsigned(&self) -> Result<(), PqHeptaHandoffError> {
        if !valid_chain(&self.chain_id)
            || !valid_did(&self.signer_did)
            || self.signer_generation == 0
            || self.signer_key_id == [0; 32]
        {
            return Err(PqHeptaHandoffError::InvalidIdentity);
        }
        self.admission.validate()?;
        Ok(())
    }

    fn unsigned_wire(&self) -> Result<Vec<u8>, PqHeptaHandoffError> {
        self.validate_unsigned()?;
        let admission = self.admission.canonical_bytes();
        if admission.len() > u16::MAX as usize {
            return Err(PqHeptaHandoffError::MalformedWire);
        }
        let mut wire = Vec::with_capacity(8 + 2 + self.chain_id.len() + self.signer_did.len()
            + 32 + 8 + 2 + admission.len());
        wire.extend_from_slice(WIRE_MAGIC);
        wire.extend_from_slice(&[HEPTA_PQ_HANDOFF_VERSION, ALGORITHM, 0, 0]);
        wire.push(self.chain_id.len() as u8);
        wire.extend_from_slice(self.chain_id.as_bytes());
        wire.push(self.signer_did.len() as u8);
        wire.extend_from_slice(self.signer_did.as_bytes());
        wire.extend_from_slice(&self.signer_key_id);
        wire.extend_from_slice(&self.signer_generation.to_be_bytes());
        wire.extend_from_slice(&(admission.len() as u16).to_be_bytes());
        wire.extend_from_slice(&admission);
        if wire.len() + ML_DSA_65_SIGNATURE_BYTES > MAX_HEPTA_PQ_HANDOFF_BYTES {
            return Err(PqHeptaHandoffError::WireTooLarge);
        }
        Ok(wire)
    }

    fn signing_message(&self) -> Result<Vec<u8>, PqHeptaHandoffError> {
        let wire = self.unsigned_wire()?;
        let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + wire.len());
        message.extend_from_slice(SIGN_DOMAIN);
        message.extend_from_slice(&wire);
        Ok(message)
    }

    pub fn encoded_bytes(&self) -> Result<Vec<u8>, PqHeptaHandoffError> {
        if self.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqHeptaHandoffError::InvalidSignature);
        }
        let mut wire = self.unsigned_wire()?;
        wire.extend_from_slice(&self.signature);
        Ok(wire)
    }

    /// Strict bounded parser. No signature is accepted, and no identity is
    /// authorized here; only verify_for_context can do those operations.
    pub fn decode_untrusted(wire: &[u8]) -> Result<Self, PqHeptaHandoffError> {
        if wire.len() > MAX_HEPTA_PQ_HANDOFF_BYTES {
            return Err(PqHeptaHandoffError::WireTooLarge);
        }
        if wire.len() < 8 + ML_DSA_65_SIGNATURE_BYTES
            || &wire[..4] != WIRE_MAGIC
            || wire[4..8] != [HEPTA_PQ_HANDOFF_VERSION, ALGORITHM, 0, 0]
        {
            return Err(PqHeptaHandoffError::MalformedWire);
        }
        let mut cursor = 8;
        let chain_len = take(wire, &mut cursor, 1)?[0] as usize;
        if chain_len == 0 || chain_len > 64 {
            return Err(PqHeptaHandoffError::InvalidIdentity);
        }
        let chain_id = std::str::from_utf8(take(wire, &mut cursor, chain_len)?)
            .map_err(|_| PqHeptaHandoffError::InvalidIdentity)?
            .to_owned();
        let did_len = take(wire, &mut cursor, 1)?[0] as usize;
        if !(5..=192).contains(&did_len) {
            return Err(PqHeptaHandoffError::InvalidIdentity);
        }
        let signer_did = std::str::from_utf8(take(wire, &mut cursor, did_len)?)
            .map_err(|_| PqHeptaHandoffError::InvalidIdentity)?
            .to_owned();
        let mut signer_key_id = [0; 32];
        signer_key_id.copy_from_slice(take(wire, &mut cursor, 32)?);
        let signer_generation = u64::from_be_bytes(
            take(wire, &mut cursor, 8)?.try_into().map_err(|_| PqHeptaHandoffError::MalformedWire)?
        );
        let admission_len = u16::from_be_bytes(
            take(wire, &mut cursor, 2)?.try_into().map_err(|_| PqHeptaHandoffError::MalformedWire)?
        ) as usize;
        let encoded_admission = take(wire, &mut cursor, admission_len)?;
        let mut decoder = Decoder::new(encoded_admission);
        let admission = HeptaArtifactAdmissionV1::decode(&mut decoder)
            .map_err(HeptaHandoffError::from)?;
        decoder.finish().map_err(HeptaHandoffError::from)?;
        if admission.canonical_bytes() != encoded_admission {
            return Err(PqHeptaHandoffError::MalformedWire);
        }
        let signature = take(wire, &mut cursor, ML_DSA_65_SIGNATURE_BYTES)?.to_vec();
        if cursor != wire.len() {
            return Err(PqHeptaHandoffError::MalformedWire);
        }
        let signed = Self {
            chain_id, signer_did, signer_key_id, signer_generation, admission, signature,
        };
        signed.validate_unsigned()?;
        if signed.encoded_bytes()? != wire {
            return Err(PqHeptaHandoffError::MalformedWire);
        }
        Ok(signed)
    }
}

fn take<'a>(
    wire: &'a [u8],
    cursor: &mut usize,
    count: usize,
) -> Result<&'a [u8], PqHeptaHandoffError> {
    let end = cursor.checked_add(count).ok_or(PqHeptaHandoffError::MalformedWire)?;
    let bytes = wire.get(*cursor..end).ok_or(PqHeptaHandoffError::MalformedWire)?;
    *cursor = end;
    Ok(bytes)
}

fn valid_chain(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.' | b':')
    })
}

fn valid_did(did: &str) -> bool {
    (5..=192).contains(&did.len())
        && did.starts_with("did:")
        && did.bytes().all(|b| b.is_ascii_graphic())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PqHeptaHandoffError {
    #[error(transparent)]
    Admission(#[from] HeptaHandoffError),
    #[error("PQ Hepta handoff wire exceeds its hard byte limit")]
    WireTooLarge,
    #[error("malformed or noncanonical PQ Hepta handoff wire")]
    MalformedWire,
    #[error("invalid PQ Hepta handoff identity")]
    InvalidIdentity,
    #[error("invalid or duplicate externally pinned PQ Hepta authority")]
    InvalidPin,
    #[error("PQ Hepta authority is not current or has been revoked")]
    RevokedOrExpired,
    #[error("unauthorized PQ Hepta authority or key generation")]
    UnauthorizedAuthority,
    #[error("ML-DSA-65 signature invalid")]
    InvalidSignature,
    #[error("current Hepta owner or chain context mismatch: {0}")]
    ContextMismatch(&'static str),
}
