//! Opt-in ML-DSA-65 Hepta admission research envelope; NOT a FinalUse token.
//! The caller, not the peer, supplies the trusted PQ public key, DID and fresh
//! owner/withdrawal snapshot. V1 Ed25519 identity is never a PQ authority.
use crate::canonical::{CanonicalCbor, CanonicalDecodeError, Decoder, Encoder, CANONICAL_ENCODING};
use crate::hepta_handoff::{HeptaArtifactAdmissionV1, HeptaHandoffError};
use ml_dsa::{
    EncodedVerifyingKey, KeyExport, Keypair, MlDsa65, Signature, SignatureEncoding, Signer,
    SigningKey, VerifyingKey,
};
use thiserror::Error;

pub const PQ_HEPTA_HANDOFF_VERSION: u8 = 2;
pub const ML_DSA_65_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SIG_BYTES: usize = 3309;
pub const MAX_PQ_HEPTA_ENVELOPE_BYTES: usize = 8192;
const DOMAIN: &str = "trnm-hepta-admission-ml-dsa65-v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPqHeptaAdmissionV2 {
    pub chain_id: String,
    pub signer_did: String,
    pub public_key: Vec<u8>,
    pub admission: HeptaArtifactAdmissionV1,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PqHeptaHandoffError {
    #[error(transparent)]
    Canonical(#[from] CanonicalDecodeError),
    #[error(transparent)]
    Admission(#[from] HeptaHandoffError),
    #[error("invalid Chain namespace")]
    InvalidChain,
    #[error("invalid Hepta owner DID")]
    InvalidDid,
    #[error("invalid ML-DSA-65 verifying key")]
    InvalidKey,
    #[error("invalid ML-DSA-65 signature encoding")]
    InvalidSignatureEncoding,
    #[error("invalid ML-DSA-65 signature")]
    InvalidSignature,
    #[error("PQ handoff exceeds 8192-byte limit")]
    TooLarge,
    #[error("canonical encoding profile mismatch")]
    InvalidEncoding,
    #[error("trusted owner context mismatch: {0}")]
    ContextMismatch(&'static str),
    #[error("trusted clock moved backwards during PQ handoff verification")]
    TimeMovedBackwards,
}

impl SignedPqHeptaAdmissionV2 {
    pub fn sign(
        chain_id: String,
        signer_did: String,
        admission: HeptaArtifactAdmissionV1,
        key: &SigningKey<MlDsa65>,
    ) -> Result<Self, PqHeptaHandoffError> {
        let mut item = Self {
            chain_id,
            signer_did,
            public_key: key.verifying_key().to_bytes().to_vec(),
            admission,
            signature: Vec::new(),
        };
        item.check_shape()?;
        let sig: Signature<MlDsa65> = key.sign(&item.signing_bytes());
        item.signature = sig.to_vec();
        Ok(item)
    }

    /// Pure ML-DSA-65 uses an empty FIPS context. Domain separation is
    /// provided by these exact signed application bytes, not by a mutable flag.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.array(7);
        e.text(DOMAIN);
        e.uint(PQ_HEPTA_HANDOFF_VERSION as u64);
        e.text(CANONICAL_ENCODING);
        e.text(&self.chain_id);
        e.text(&self.signer_did);
        e.bytes(&self.public_key);
        self.admission.encode_canonical(&mut e);
        e.finish()
    }

    fn check_shape(&self) -> Result<(), PqHeptaHandoffError> {
        if self.chain_id.is_empty()
            || self.chain_id.len() > 64
            || !self.chain_id.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(PqHeptaHandoffError::InvalidChain);
        }
        if !(5..=192).contains(&self.signer_did.len())
            || !self.signer_did.starts_with("did:")
            || !self.signer_did.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(PqHeptaHandoffError::InvalidDid);
        }
        if self.public_key.len() != ML_DSA_65_KEY_BYTES {
            return Err(PqHeptaHandoffError::InvalidKey);
        }
        self.admission.validate()?;
        Ok(())
    }

    /// A signature over an embedded key is NOT an authorized Hepta identity.
    /// Keep this primitive private: only verify_for_context is an entrypoint.
    fn verify_self_signature(&self) -> Result<(), PqHeptaHandoffError> {
        self.check_shape()?;
        if self.signature.len() != ML_DSA_65_SIG_BYTES {
            return Err(PqHeptaHandoffError::InvalidSignatureEncoding);
        }
        let signature = Signature::<MlDsa65>::try_from(self.signature.as_slice())
            .map_err(|_| PqHeptaHandoffError::InvalidSignatureEncoding)?;
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(self.public_key.as_slice())
            .map_err(|_| PqHeptaHandoffError::InvalidKey)?;
        if !VerifyingKey::<MlDsa65>::decode(&encoded).verify_with_context(
            &self.signing_bytes(),
            &[],
            &signature,
        ) {
            return Err(PqHeptaHandoffError::InvalidSignature);
        }
        Ok(())
    }

    /// All expectations MUST be obtained independently from the current
    /// Hepta Control authority, not copied from received untrusted bytes.
    /// This returns no capability to install, replay, release or spend.
    pub fn verify_for_context(
        &self,
        trusted_chain: &str,
        trusted_did: &str,
        trusted_ml_dsa65_key: &[u8],
        trusted_admission: &HeptaArtifactAdmissionV1,
        now_unix_s: u64,
    ) -> Result<(), PqHeptaHandoffError> {
        trusted_admission.validate_at(now_unix_s)?;
        if trusted_ml_dsa65_key.len() != ML_DSA_65_KEY_BYTES {
            return Err(PqHeptaHandoffError::InvalidKey);
        }
        if self.chain_id != trusted_chain {
            return Err(PqHeptaHandoffError::ContextMismatch("chain"));
        }
        if self.signer_did != trusted_did {
            return Err(PqHeptaHandoffError::ContextMismatch("did"));
        }
        if self.public_key != trusted_ml_dsa65_key {
            return Err(PqHeptaHandoffError::ContextMismatch("key"));
        }
        if &self.admission != trusted_admission {
            return Err(PqHeptaHandoffError::ContextMismatch("admission"));
        }
        self.verify_self_signature()
    }

    /// Re-sample a caller-trusted clock after the ML-DSA operation. An
    /// admission that was valid before signature verification may have
    /// expired by the time the verified result is returned. Clock rollback
    /// must not revive it. This read-only result is still NOT FinalUse.
    pub fn verify_for_context_with_fresh_time(
        &self,
        trusted_chain: &str,
        trusted_did: &str,
        trusted_ml_dsa65_key: &[u8],
        trusted_admission: &HeptaArtifactAdmissionV1,
        now_unix_s: u64,
        after_verify_unix_s: impl FnOnce() -> u64,
    ) -> Result<(), PqHeptaHandoffError> {
        self.verify_for_context(
            trusted_chain,
            trusted_did,
            trusted_ml_dsa65_key,
            trusted_admission,
            now_unix_s,
        )?;
        let post_verify_unix_s = after_verify_unix_s();
        if post_verify_unix_s < now_unix_s {
            return Err(PqHeptaHandoffError::TimeMovedBackwards);
        }
        trusted_admission.validate_at(post_verify_unix_s)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        CanonicalCbor::canonical_bytes(self)
    }

    /// Backward-compatible self-signature-verified parser. This verifies the
    /// embedded, untrusted key, but does not authenticate a Hepta owner.
    /// Do not use this as an authority or as a cheap untrusted ingress guard.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PqHeptaHandoffError> {
        let item = Self::parse_untrusted_canonical_bytes(bytes)?;
        item.verify_self_signature()?;
        Ok(item)
    }

    /// Preferred bounded receiving path when independent Hepta Control facts
    /// are available: cheap parse/shape/context checks BEFORE costly ML-DSA,
    /// exactly one signature verification, and fresh-time check AFTER it.
    /// Caller MUST recheck mutable withdrawal/operation ownership atomically
    /// at actual use; this function does not grant any capability.
    pub fn from_canonical_bytes_for_context(
        bytes: &[u8],
        trusted_chain: &str,
        trusted_did: &str,
        trusted_ml_dsa65_key: &[u8],
        trusted_admission: &HeptaArtifactAdmissionV1,
        now_unix_s: u64,
        after_verify_unix_s: impl FnOnce() -> u64,
    ) -> Result<Self, PqHeptaHandoffError> {
        let item = Self::parse_untrusted_canonical_bytes(bytes)?;
        item.verify_for_context_with_fresh_time(
            trusted_chain,
            trusted_did,
            trusted_ml_dsa65_key,
            trusted_admission,
            now_unix_s,
            after_verify_unix_s,
        )?;
        Ok(item)
    }

    /// Strict canonical decode is data only: no embedded self-signature
    /// verification and no trust is derived from the received public key.
    fn parse_untrusted_canonical_bytes(bytes: &[u8]) -> Result<Self, PqHeptaHandoffError> {
        if bytes.len() > MAX_PQ_HEPTA_ENVELOPE_BYTES {
            return Err(PqHeptaHandoffError::TooLarge);
        }
        let mut d = Decoder::new(bytes);
        d.array(7)?;
        let version = d.uint()?;
        if version != PQ_HEPTA_HANDOFF_VERSION as u64 {
            return Err(CanonicalDecodeError::UnsupportedVersion(version).into());
        }
        if d.text()? != CANONICAL_ENCODING {
            return Err(PqHeptaHandoffError::InvalidEncoding);
        }
        let chain_id = d.text()?;
        let signer_did = d.text()?;
        let key = d.bytes()?;
        if key.len() != ML_DSA_65_KEY_BYTES {
            return Err(PqHeptaHandoffError::InvalidKey);
        }
        let public_key = key.to_vec();
        let admission = HeptaArtifactAdmissionV1::decode(&mut d)?;
        let signature = d.bytes()?;
        if signature.len() != ML_DSA_65_SIG_BYTES {
            return Err(PqHeptaHandoffError::InvalidSignatureEncoding);
        }
        let signature = signature.to_vec();
        d.finish()?;
        let item = Self {
            chain_id,
            signer_did,
            public_key,
            admission,
            signature,
        };
        if item.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::NonCanonicalRoundTrip.into());
        }
        item.check_shape()?;
        Ok(item)
    }
}

impl CanonicalCbor for SignedPqHeptaAdmissionV2 {
    fn encode_canonical(&self, e: &mut Encoder) {
        e.array(7);
        e.uint(PQ_HEPTA_HANDOFF_VERSION as u64);
        e.text(CANONICAL_ENCODING);
        e.text(&self.chain_id);
        e.text(&self.signer_did);
        e.bytes(&self.public_key);
        self.admission.encode_canonical(e);
        e.bytes(&self.signature);
    }
}
