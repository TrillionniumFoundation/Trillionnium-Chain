//! Canonical, in-process FIPS 204 ML-DSA-65 authentication.
//!
//! All acceptance uses one RustCrypto verifier, pure ML-DSA with empty context.
//! Callers put their versioned application domain in the exact signed message.
//! The optional OpenSSL adapter is an independent signing source: its output
//! must pass the same canonical verifier. There is no classical/second-backend
//! OR path. Cryptographic observations grant no role, nonce, funds or FinalUse.
//!
//! This integration is not an independent cryptographic implementation audit.

use ml_dsa::{KeyInit, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "pq-native-openssl")]
use openssl::{
    error::ErrorStack,
    pkey::{KeyType, PKey, Private},
    sign::Signer as OpenSslSigner,
};
use std::fmt;
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, preflight_unverified_with_spki, PqFrameError, PqFrameExpectation,
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SPKI_BYTES, TPQ1_SIGNED_BYTES,
    TPQ1_UNSIGNED_BYTES,
};
use zeroize::Zeroizing;

pub const PQ_MAX_MESSAGE_BYTES: usize = 65_536;
const SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

#[derive(Debug)]
pub enum PqNativeError {
    Frame(PqFrameError),
    KeyAlgorithm,
    KeyPin,
    SignatureRejected,
    #[cfg(feature = "pq-native-openssl")]
    Backend(ErrorStack),
    #[cfg(feature = "pq-native-openssl")]
    OpenSslVersion,
}
impl fmt::Display for PqNativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "PQ preflight rejected: {error:?}"),
            Self::KeyAlgorithm => f.write_str("exact ML-DSA-65 key required"),
            Self::KeyPin => f.write_str("ML-DSA-65 public key does not match caller pin"),
            Self::SignatureRejected => f.write_str("ML-DSA-65 signature rejected"),
            #[cfg(feature = "pq-native-openssl")]
            Self::Backend(error) => write!(f, "ML-DSA-65 signing provider rejected: {error}"),
            #[cfg(feature = "pq-native-openssl")]
            Self::OpenSslVersion => f.write_str("OpenSSL 3.5 or later is required"),
        }
    }
}
impl std::error::Error for PqNativeError {}
impl From<PqFrameError> for PqNativeError {
    fn from(value: PqFrameError) -> Self {
        Self::Frame(value)
    }
}
#[cfg(feature = "pq-native-openssl")]
impl From<ErrorStack> for PqNativeError {
    fn from(value: ErrorStack) -> Self {
        Self::Backend(value)
    }
}

/// Only actual verification constructs this borrowed observation. It is not an
/// application permission and deliberately has no Deserialize/public constructor.
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
    pub fn statement(&self) -> &'a [u8] {
        self.authenticated_statement()
    }
}

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

/// Strict SPKI, algorithm and independently supplied identity pin are checked
/// before public-key expansion. Current role/generation/lifetime remain the
/// application owner's responsibility on every operation, including cache hits.
pub struct PqNativeVerifier {
    key: VerifyingKey<MlDsa65>,
    spki: [u8; ML_DSA_65_SPKI_BYTES],
    key_id: [u8; 32],
}
impl PqNativeVerifier {
    pub fn from_pinned_spki(spki: &[u8], expected_key_id: [u8; 32]) -> Result<Self, PqNativeError> {
        let key_id = ml_dsa_65_key_id_from_spki(spki)?;
        if key_id != expected_key_id {
            return Err(PqNativeError::KeyPin);
        }
        let key = VerifyingKey::<MlDsa65>::new_from_slice(&spki[SPKI_PREFIX.len()..])
            .map_err(|_| PqNativeError::KeyAlgorithm)?;
        let mut fixed_spki = [0; ML_DSA_65_SPKI_BYTES];
        fixed_spki.copy_from_slice(spki);
        Ok(Self {
            key,
            spki: fixed_spki,
            key_id,
        })
    }
    pub fn public_key_id(&self) -> [u8; 32] {
        self.key_id
    }
    pub fn public_spki(&self) -> &[u8; ML_DSA_65_SPKI_BYTES] {
        &self.spki
    }
    pub fn verify<'a>(
        &self,
        frame: &'a [u8],
        expected: &PqFrameExpectation<'_>,
    ) -> Result<PqSignatureObservation<'a>, PqNativeError> {
        let checked = preflight_unverified_with_spki(frame, expected, &self.spki)?;
        self.verify_exact_message(checked.unsigned_statement(), checked.unverified_signature())?;
        Ok(PqSignatureObservation {
            frame,
            signer_key_id: self.key_id,
        })
    }

    /// FIPS 204 pure ML-DSA, empty context; no prehash/internal/raw-mu shortcut.
    /// Failed verification must still consume the caller's reserved CPU budget.
    pub fn verify_exact_message<'a>(
        &self,
        message: &'a [u8],
        signature: &[u8],
    ) -> Result<PqMessageObservation<'a>, PqNativeError> {
        if message.len() > PQ_MAX_MESSAGE_BYTES || signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(PqNativeError::SignatureRejected);
        }
        let signature = Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| PqNativeError::SignatureRejected)?;
        self.key
            .verify(message, &signature)
            .map_err(|_| PqNativeError::SignatureRejected)?;
        Ok(PqMessageObservation {
            message,
            signer_key_id: self.key_id,
        })
    }
}

enum OwnedSigningBackend {
    RustCrypto(SigningKey<MlDsa65>),
    #[cfg(feature = "pq-native-openssl")]
    OpenSsl(PKey<Private>),
}

/// Owned, non-Clone secret key. This layer does not load files, authorize intents,
/// generate implicit keys, export secrets, or claim HSM/side-channel qualification.
pub struct PqNativeSigningKey {
    key: OwnedSigningBackend,
    verifier: PqNativeVerifier,
}
impl PqNativeSigningKey {
    /// Public identity derivation for explicit key provisioning. This is not a
    /// trust root: an application's expected pin must come from its own owner.
    pub fn public_spki_from_seed(seed: &Zeroizing<[u8; 32]>) -> [u8; ML_DSA_65_SPKI_BYTES] {
        let key = SigningKey::<MlDsa65>::new_from_slice(seed.as_ref())
            .expect("fixed ML-DSA-65 seed length");
        public_spki(&key)
    }
    pub fn from_owned_seed(
        seed: Zeroizing<[u8; 32]>,
        expected_key_id: [u8; 32],
    ) -> Result<Self, PqNativeError> {
        let key = SigningKey::<MlDsa65>::new_from_slice(seed.as_ref())
            .map_err(|_| PqNativeError::KeyAlgorithm)?;
        // Both the input owner and ml-dsa's expanded key use zeroize-on-drop.
        drop(seed);
        let verifier = PqNativeVerifier::from_pinned_spki(&public_spki(&key), expected_key_id)?;
        Ok(Self {
            key: OwnedSigningBackend::RustCrypto(key),
            verifier,
        })
    }
    #[cfg(feature = "pq-native-openssl")]
    pub fn from_owned_key(
        key: PKey<Private>,
        expected_key_id: [u8; 32],
    ) -> Result<Self, PqNativeError> {
        if openssl::version::number() < 0x3050_0000 {
            return Err(PqNativeError::OpenSslVersion);
        }
        if !key.is_a(KeyType::ML_DSA_65) {
            return Err(PqNativeError::KeyAlgorithm);
        }
        let verifier =
            PqNativeVerifier::from_pinned_spki(&key.public_key_to_der()?, expected_key_id)?;
        Ok(Self {
            key: OwnedSigningBackend::OpenSsl(key),
            verifier,
        })
    }
    pub fn public_key_id(&self) -> [u8; 32] {
        self.verifier.key_id
    }
    pub fn public_spki(&self) -> &[u8; ML_DSA_65_SPKI_BYTES] {
        &self.verifier.spki
    }
    pub fn sign_exact_message(
        &self,
        message: &[u8],
    ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], PqNativeError> {
        if message.len() > PQ_MAX_MESSAGE_BYTES {
            return Err(PqNativeError::SignatureRejected);
        }
        let mut result = [0; ML_DSA_65_SIGNATURE_BYTES];
        match &self.key {
            OwnedSigningBackend::RustCrypto(key) => {
                // FIPS 204 permits deterministic pure signing; the verifier is
                // identical for hedged signatures supplied by other providers.
                let signature: Signature<MlDsa65> = key
                    .try_sign(message)
                    .map_err(|_| PqNativeError::SignatureRejected)?;
                result.copy_from_slice(&signature.encode());
            }
            #[cfg(feature = "pq-native-openssl")]
            OwnedSigningBackend::OpenSsl(key) => {
                let mut signer = OpenSslSigner::new_without_digest(key)?;
                if signer.sign_oneshot(&mut result, message)? != ML_DSA_65_SIGNATURE_BYTES {
                    return Err(PqNativeError::SignatureRejected);
                }
            }
        }
        self.verifier.verify_exact_message(message, &result)?;
        Ok(result)
    }
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
        preflight_unverified_with_spki(&frame, expected, &self.verifier.spki)?;
        frame[TPQ1_UNSIGNED_BYTES + 2..].copy_from_slice(&self.sign_exact_message(statement)?);
        self.verifier.verify(&frame, expected)?;
        Ok(frame)
    }
}
fn public_spki(key: &SigningKey<MlDsa65>) -> [u8; ML_DSA_65_SPKI_BYTES] {
    let mut spki = [0; ML_DSA_65_SPKI_BYTES];
    spki[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    spki[SPKI_PREFIX.len()..].copy_from_slice(&key.verifying_key().encode());
    spki
}

/// Compatibility entry point for native account/task owners. The expected
/// identity remains caller-pinned and all verification uses the canonical path.
pub fn verify_tpq1<'a>(
    frame: &'a [u8],
    expected: &PqFrameExpectation<'_>,
    spki: &[u8],
) -> Result<SignatureCheckedPqFrame<'a>, PqAuthError> {
    let checked =
        preflight_unverified_with_spki(frame, expected, spki).map_err(PqAuthError::Frame)?;
    verify_ml_dsa_65(
        &spki[SPKI_PREFIX.len()..],
        checked.unsigned_statement(),
        &[],
        checked.unverified_signature(),
    )?;
    Ok(PqSignatureObservation {
        frame,
        signer_key_id: expected.signer_key_id,
    })
}

pub type SignatureCheckedPqFrame<'a> = PqSignatureObservation<'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAuthError {
    Frame(PqFrameError),
    PublicKeyLength,
    SignatureEncoding,
    ContextLength,
    MessageLength,
    Signature,
}

/// Exact low-level FIPS 204 verifier retained for the native research account
/// owner and independent vectors. Context is explicit; applications must choose
/// one domain policy and must never retry with another context after failure.
/// Supplied key bytes alone are not an identity or role authorization.
pub fn verify_ml_dsa_65(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), PqAuthError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(PqAuthError::PublicKeyLength);
    }
    if context.len() > 255 {
        return Err(PqAuthError::ContextLength);
    }
    if message.len() > PQ_MAX_MESSAGE_BYTES {
        return Err(PqAuthError::MessageLength);
    }
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(PqAuthError::SignatureEncoding);
    }
    let signature =
        Signature::<MlDsa65>::try_from(signature).map_err(|_| PqAuthError::SignatureEncoding)?;
    let key = VerifyingKey::<MlDsa65>::new_from_slice(public_key)
        .map_err(|_| PqAuthError::PublicKeyLength)?;
    if !key.verify_with_context(message, context, &signature) {
        return Err(PqAuthError::Signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
