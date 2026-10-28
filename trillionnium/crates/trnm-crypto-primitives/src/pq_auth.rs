//! Actual in-process ML-DSA-65 for the exact native TPQ1 frame.
//!
//! This optional development adapter calls OpenSSL EVP through Rust's safe
//! bindings; it never accepts a CLI exit status or a caller's verification bool.
//! It has no classical fallback. Signature validity does not consume a nonce,
//! admit a block, grant FinalUse or migrate installed account/signer authority.
//! The native ledger, key custody and versioned activation owners remain separate.

use openssl::error::ErrorStack;
use openssl::pkey::{KeyType, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use std::fmt;
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, preflight_unverified_with_spki, PqFrameError, PqFrameExpectation,
    ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES, TPQ1_SIGNED_BYTES, TPQ1_UNSIGNED_BYTES,
};

#[derive(Debug)]
pub enum PqNativeError {
    Frame(PqFrameError),
    KeyAlgorithm,
    KeyPin,
    Backend(ErrorStack),
    SignatureRejected,
    OpenSslVersion,
}

impl fmt::Display for PqNativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "TPQ1 preflight rejected: {error:?}"),
            Self::KeyAlgorithm => f.write_str("exact ML-DSA-65 key required"),
            Self::KeyPin => f.write_str("ML-DSA-65 public key does not match caller pin"),
            Self::Backend(error) => write!(f, "ML-DSA-65 provider rejected operation: {error}"),
            Self::SignatureRejected => f.write_str("ML-DSA-65 signature rejected"),
            Self::OpenSslVersion => f.write_str("OpenSSL 3.5 or later is required"),
        }
    }
}

impl std::error::Error for PqNativeError {}

impl From<PqFrameError> for PqNativeError {
    fn from(error: PqFrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<ErrorStack> for PqNativeError {
    fn from(error: ErrorStack) -> Self {
        Self::Backend(error)
    }
}

fn require_provider_version() -> Result<(), PqNativeError> {
    if openssl::version::number() < 0x3050_0000 {
        return Err(PqNativeError::OpenSslVersion);
    }
    Ok(())
}

/// The only constructor performs actual signature verification on this borrowed
/// frame. There is deliberately no Deserialize, Clone or public field constructor.
/// This observation proves cryptographic validity only, not application authority.
///
/// ```compile_fail
/// use trnm_crypto_primitives::pq_auth::PqSignatureObservation;
/// let forged = PqSignatureObservation {};
/// ```
#[derive(Debug)]
pub struct PqSignatureObservation<'a> {
    frame: &'a [u8],
    signer_key_id: [u8; 32],
}

impl<'a> PqSignatureObservation<'a> {
    pub fn authenticated_statement(&self) -> &'a [u8] {
        &self.frame[..TPQ1_UNSIGNED_BYTES]
    }

    pub fn signer_key_id(&self) -> &[u8; 32] {
        &self.signer_key_id
    }
}

/// Reusable public-key handle. DER grammar and independently supplied key-ID
/// pin are fixed at construction; every frame still checks all caller context.
pub struct PqNativeVerifier {
    key: PKey<Public>,
    spki: [u8; ML_DSA_65_SPKI_BYTES],
    key_id: [u8; 32],
}

impl PqNativeVerifier {
    pub fn from_pinned_spki(spki: &[u8], expected_key_id: [u8; 32]) -> Result<Self, PqNativeError> {
        require_provider_version()?;
        let key_id = ml_dsa_65_key_id_from_spki(spki)?;
        if key_id != expected_key_id {
            return Err(PqNativeError::KeyPin);
        }
        let key = PKey::public_key_from_der(spki)?;
        // Provider-supplied ML-DSA keys have no dependable numeric EVP_PKEY_id.
        if !key.is_a(KeyType::ML_DSA_65) || key.public_key_to_der()? != spki {
            return Err(PqNativeError::KeyAlgorithm);
        }
        let mut fixed_spki = [0; ML_DSA_65_SPKI_BYTES];
        fixed_spki.copy_from_slice(spki);
        Ok(Self {
            key,
            spki: fixed_spki,
            key_id,
        })
    }

    pub fn verify<'a>(
        &self,
        frame: &'a [u8],
        expected: &PqFrameExpectation<'_>,
    ) -> Result<PqSignatureObservation<'a>, PqNativeError> {
        let unverified = preflight_unverified_with_spki(frame, expected, &self.spki)?;
        self.verify_exact_message(
            unverified.unsigned_statement(),
            unverified.unverified_signature(),
        )?;
        Ok(PqSignatureObservation {
            frame,
            signer_key_id: self.key_id,
        })
    }

    /// Actual same-provider ML-DSA verification for the existing PQG1 migration
    /// domain, whose historical wire signs a complete domain-separated message
    /// directly. The caller must construct that exact expected message from
    /// independently pinned source/account state; no account authority is minted.
    pub fn verify_exact_message<'a>(
        &self,
        message: &'a [u8],
        signature: &[u8],
    ) -> Result<PqMessageObservation<'a>, PqNativeError> {
        if message.len() > 65536 || signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqNativeError::SignatureRejected);
        }
        let mut verifier = Verifier::new_without_digest(&self.key)?;
        if !verifier.verify_oneshot(signature, message)? {
            return Err(PqNativeError::SignatureRejected);
        }
        Ok(PqMessageObservation {
            message,
            signer_key_id: self.key_id,
        })
    }
}

/// Opaque cryptographic observation only, never a source/migration permission.
pub struct PqMessageObservation<'a> {
    message: &'a [u8],
    signer_key_id: [u8; 32],
}
impl<'a> PqMessageObservation<'a> {
    pub fn authenticated_message(&self) -> &'a [u8] {
        self.message
    }
    pub fn signer_key_id(&self) -> &[u8; 32] {
        &self.signer_key_id
    }
}

/// An already-owned private key, supplied by the caller's key-custody owner.
/// No key files, process execution, implicit key generation, HSM claims or key
/// export are implemented here. Callers must separately authorize every intent.
pub struct PqNativeSigningKey {
    key: PKey<Private>,
    verifier: PqNativeVerifier,
}

impl PqNativeSigningKey {
    /// Public identity only; the private EVP key is never exported.
    pub fn public_key_id(&self) -> [u8; 32] {
        self.verifier.key_id
    }

    pub fn public_spki(&self) -> &[u8; ML_DSA_65_SPKI_BYTES] {
        &self.verifier.spki
    }

    pub fn from_owned_key(
        key: PKey<Private>,
        expected_key_id: [u8; 32],
    ) -> Result<Self, PqNativeError> {
        require_provider_version()?;
        if !key.is_a(KeyType::ML_DSA_65) {
            return Err(PqNativeError::KeyAlgorithm);
        }
        let verifier =
            PqNativeVerifier::from_pinned_spki(&key.public_key_to_der()?, expected_key_id)?;
        Ok(Self { key, verifier })
    }

    /// Sign exactly the same TPQ1 statement validated by the native parser.
    /// Randomized signatures must not be used as new logical operation IDs.
    pub fn sign_statement(
        &self,
        statement: &[u8],
        expected: &PqFrameExpectation<'_>,
    ) -> Result<[u8; TPQ1_SIGNED_BYTES], PqNativeError> {
        if statement.len() != TPQ1_UNSIGNED_BYTES {
            return Err(PqFrameError::FrameLength.into());
        }
        let mut frame = [0; TPQ1_SIGNED_BYTES];
        frame[..TPQ1_UNSIGNED_BYTES].copy_from_slice(statement);
        frame[TPQ1_UNSIGNED_BYTES..TPQ1_UNSIGNED_BYTES + 2]
            .copy_from_slice(&(ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
        // The temporary all-zero signature is syntax-only and never returned.
        // It cannot construct PqSignatureObservation or skip the EVP call below.
        preflight_unverified_with_spki(&frame, expected, &self.verifier.spki)?;
        let mut signer = Signer::new_without_digest(&self.key)?;
        let length = signer.sign_oneshot(&mut frame[TPQ1_UNSIGNED_BYTES + 2..], statement)?;
        if length != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqNativeError::SignatureRejected);
        }
        // Check actual provider output against the exact pinned native context.
        self.verifier.verify(&frame, expected)?;
        Ok(frame)
    }
}
