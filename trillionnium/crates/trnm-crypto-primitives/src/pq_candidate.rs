//! Explicit ML-DSA parameter candidates for local mathematical observations.
//!
//! This module does not activate ML-DSA-87 or grant transaction, migration,
//! governance, release, CURRENT, FinalUse or recovery authority. A caller must
//! obtain the algorithm and public key from its trusted owner; neither is chosen
//! by an incoming message. The deployed profile remains an independent decision.
//!
//! Both candidates use FIPS 204 Pure ML-DSA with an empty FIPS context. A versioned
//! application domain belongs in the exact message bytes. There is no context,
//! prehash, raw-mu, alternate-suite or classical verification fallback. This API
//! cannot determine whether a caller mistakenly supplied a digest as its message.
//!
//! Signing uses the deterministic FIPS variant and an explicitly owned seed for
//! reproducible candidate evaluation. It does not obtain entropy, load keys,
//! export secrets, or claim independent implementation or side-channel review.

use ml_dsa::{
    KeyInit, Keypair, MlDsa65, MlDsa87, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use std::fmt;
use zeroize::Zeroizing;

pub const CANDIDATE_MAX_MESSAGE_BYTES: usize =
    trnm_protocol::crypto_profile::MAX_SIGNED_MESSAGE_BYTES;

/// FIPS 204 parameter sets, not whole-system security levels or activation IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAlgorithm {
    MlDsa65,
    MlDsa87,
}

impl CandidateAlgorithm {
    pub const ALL: [Self; 2] = [Self::MlDsa65, Self::MlDsa87];

    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Exact raw FIPS 204 public-key encoding length; this excludes DER/SPKI.
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => 1_952,
            Self::MlDsa87 => 2_592,
        }
    }

    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => 3_309,
            Self::MlDsa87 => 4_627,
        }
    }

    /// Relative NIST security category, never a count of quantum security bits.
    pub const fn nist_category(self) -> u8 {
        match self {
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateError {
    PublicKeyLength { expected: usize, actual: usize },
    SignatureLength { expected: usize, actual: usize },
    MessageTooLarge { actual: usize },
    KeyEncoding,
    SignatureEncoding,
    SignatureRejected,
    SigningFailed,
}

impl fmt::Display for CandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "candidate public key is {actual} bytes; expected {expected}"
                )
            }
            Self::SignatureLength { expected, actual } => {
                write!(
                    f,
                    "candidate signature is {actual} bytes; expected {expected}"
                )
            }
            Self::MessageTooLarge { actual } => write!(
                f,
                "candidate message is {actual} bytes; limit is {CANDIDATE_MAX_MESSAGE_BYTES}"
            ),
            Self::KeyEncoding => f.write_str("candidate key encoding rejected"),
            Self::SignatureEncoding => f.write_str("candidate signature encoding rejected"),
            Self::SignatureRejected => f.write_str("candidate signature verification rejected"),
            Self::SigningFailed => f.write_str("candidate signing failed"),
        }
    }
}

impl std::error::Error for CandidateError {}

enum CandidateVerifyingBackend {
    MlDsa65(VerifyingKey<MlDsa65>),
    MlDsa87(VerifyingKey<MlDsa87>),
}

/// A fixed algorithm/key pair. Successful verification is only a mathematical
/// observation. Current permissions, generation, revocation and budgets still
/// require the application owner's checks on every effect, including cache hits.
pub struct CandidateVerifier {
    key: CandidateVerifyingBackend,
    raw_public_key: Vec<u8>,
}

impl CandidateVerifier {
    /// `trusted_raw_pk` must be the independently pinned raw key, not a key copied
    /// from an unauthenticated envelope. Exact lengths are checked before key
    /// expansion. Unknown algorithms cannot be constructed through this API.
    pub fn from_pinned_raw(
        algorithm: CandidateAlgorithm,
        trusted_raw_pk: &[u8],
    ) -> Result<Self, CandidateError> {
        if trusted_raw_pk.len() != algorithm.public_key_bytes() {
            return Err(CandidateError::PublicKeyLength {
                expected: algorithm.public_key_bytes(),
                actual: trusted_raw_pk.len(),
            });
        }
        let key = match algorithm {
            CandidateAlgorithm::MlDsa65 => CandidateVerifyingBackend::MlDsa65(
                VerifyingKey::<MlDsa65>::new_from_slice(trusted_raw_pk)
                    .map_err(|_| CandidateError::KeyEncoding)?,
            ),
            CandidateAlgorithm::MlDsa87 => CandidateVerifyingBackend::MlDsa87(
                VerifyingKey::<MlDsa87>::new_from_slice(trusted_raw_pk)
                    .map_err(|_| CandidateError::KeyEncoding)?,
            ),
        };
        Ok(Self {
            key,
            raw_public_key: trusted_raw_pk.to_vec(),
        })
    }

    pub fn algorithm(&self) -> CandidateAlgorithm {
        match &self.key {
            CandidateVerifyingBackend::MlDsa65(_) => CandidateAlgorithm::MlDsa65,
            CandidateVerifyingBackend::MlDsa87(_) => CandidateAlgorithm::MlDsa87,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.raw_public_key
    }

    /// Verify the exact bounded message with Pure ML-DSA and empty FIPS context.
    /// Length and canonical signature decoding failures occur before signature
    /// arithmetic. Failed attempts must still consume the owner's attempt budget.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CandidateError> {
        check_message(message)?;
        let expected = self.algorithm().signature_bytes();
        if signature.len() != expected {
            return Err(CandidateError::SignatureLength {
                expected,
                actual: signature.len(),
            });
        }
        match &self.key {
            CandidateVerifyingBackend::MlDsa65(key) => {
                let signature = Signature::<MlDsa65>::try_from(signature)
                    .map_err(|_| CandidateError::SignatureEncoding)?;
                key.verify(message, &signature)
                    .map_err(|_| CandidateError::SignatureRejected)
            }
            CandidateVerifyingBackend::MlDsa87(key) => {
                let signature = Signature::<MlDsa87>::try_from(signature)
                    .map_err(|_| CandidateError::SignatureEncoding)?;
                key.verify(message, &signature)
                    .map_err(|_| CandidateError::SignatureRejected)
            }
        }
    }
}

enum CandidateSigningBackend {
    MlDsa65(SigningKey<MlDsa65>),
    MlDsa87(SigningKey<MlDsa87>),
}

/// Non-Clone owned candidate key. The input owner and the dependency's signing
/// key use zeroize-on-drop. No key files, entropy source or activation are hidden
/// in construction; fixed benchmark seeds must never provision a real identity.
pub struct CandidateSigningKey {
    key: CandidateSigningBackend,
    verifier: CandidateVerifier,
}

impl CandidateSigningKey {
    pub fn from_owned_seed(
        algorithm: CandidateAlgorithm,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, CandidateError> {
        let (key, public_key) = match algorithm {
            CandidateAlgorithm::MlDsa65 => {
                let key = SigningKey::<MlDsa65>::new_from_slice(seed.as_ref())
                    .map_err(|_| CandidateError::KeyEncoding)?;
                let public_key = key.verifying_key().encode().to_vec();
                (CandidateSigningBackend::MlDsa65(key), public_key)
            }
            CandidateAlgorithm::MlDsa87 => {
                let key = SigningKey::<MlDsa87>::new_from_slice(seed.as_ref())
                    .map_err(|_| CandidateError::KeyEncoding)?;
                let public_key = key.verifying_key().encode().to_vec();
                (CandidateSigningBackend::MlDsa87(key), public_key)
            }
        };
        drop(seed);
        let verifier = CandidateVerifier::from_pinned_raw(algorithm, &public_key)?;
        Ok(Self { key, verifier })
    }

    pub fn algorithm(&self) -> CandidateAlgorithm {
        self.verifier.algorithm()
    }

    pub fn public_key(&self) -> &[u8] {
        self.verifier.public_key()
    }

    /// Deterministic Pure signing followed by canonical self-verification. A
    /// signature is returned only after this same algorithm/key accepts it.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CandidateError> {
        check_message(message)?;
        let signature = match &self.key {
            CandidateSigningBackend::MlDsa65(key) => {
                let signature: Signature<MlDsa65> = key
                    .try_sign(message)
                    .map_err(|_| CandidateError::SigningFailed)?;
                signature.encode().to_vec()
            }
            CandidateSigningBackend::MlDsa87(key) => {
                let signature: Signature<MlDsa87> = key
                    .try_sign(message)
                    .map_err(|_| CandidateError::SigningFailed)?;
                signature.encode().to_vec()
            }
        };
        self.verifier.verify(message, &signature)?;
        Ok(signature)
    }
}

fn check_message(message: &[u8]) -> Result<(), CandidateError> {
    if message.len() > CANDIDATE_MAX_MESSAGE_BYTES {
        Err(CandidateError::MessageTooLarge {
            actual: message.len(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::MlDsaParams;
    use sha2::{Digest, Sha512};

    fn signer(algorithm: CandidateAlgorithm, seed: u8) -> CandidateSigningKey {
        CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new([seed; 32])).unwrap()
    }

    #[test]
    fn fips_lengths_categories_and_bounded_messages_match_both_candidates() {
        for (algorithm, pk_bytes, sig_bytes, category) in [
            (CandidateAlgorithm::MlDsa65, 1_952, 3_309, 3),
            (CandidateAlgorithm::MlDsa87, 2_592, 4_627, 5),
        ] {
            let signer = signer(algorithm, 31);
            let verifier =
                CandidateVerifier::from_pinned_raw(algorithm, signer.public_key()).unwrap();
            assert_eq!(algorithm.public_key_bytes(), pk_bytes);
            assert_eq!(algorithm.signature_bytes(), sig_bytes);
            assert_eq!(algorithm.nist_category(), category);
            assert_eq!(signer.algorithm(), algorithm);
            assert_eq!(signer.public_key().len(), pk_bytes);
            assert_eq!(verifier.public_key(), signer.public_key());
            for len in [0, 176, 4_096, CANDIDATE_MAX_MESSAGE_BYTES] {
                let message = vec![0x3c; len];
                let signature = signer.sign(&message).unwrap();
                assert_eq!(signature.len(), sig_bytes);
                assert_eq!(verifier.verify(&message, &signature), Ok(()));
            }
        }
    }

    #[test]
    fn deterministic_candidate_seeds_have_no_implicit_key_or_nonce_source() {
        for algorithm in CandidateAlgorithm::ALL {
            let first = signer(algorithm, 32);
            let second = signer(algorithm, 32);
            let message = b"TRNM/Test/PQCandidate/v1\0deterministic fixture";
            assert_eq!(first.public_key(), second.public_key());
            assert_eq!(first.sign(message).unwrap(), second.sign(message).unwrap());
        }
    }

    #[test]
    fn exact_key_and_signature_lengths_reject_truncation_and_trailing_bytes() {
        for algorithm in CandidateAlgorithm::ALL {
            let signer = signer(algorithm, 33);
            let pk = signer.public_key();
            for len in [0, pk.len() - 1] {
                assert!(matches!(
                    CandidateVerifier::from_pinned_raw(algorithm, &pk[..len]),
                    Err(CandidateError::PublicKeyLength { .. })
                ));
            }
            let mut appended_key = pk.to_vec();
            appended_key.push(0);
            assert!(matches!(
                CandidateVerifier::from_pinned_raw(algorithm, &appended_key),
                Err(CandidateError::PublicKeyLength { .. })
            ));
            let verifier = CandidateVerifier::from_pinned_raw(algorithm, pk).unwrap();
            let message = b"TRNM/Test/PQCandidate/v1\0lengths";
            let signature = signer.sign(message).unwrap();
            for len in [0, signature.len() - 1] {
                assert!(matches!(
                    verifier.verify(message, &signature[..len]),
                    Err(CandidateError::SignatureLength { .. })
                ));
            }
            let mut appended_signature = signature;
            appended_signature.push(0);
            assert!(matches!(
                verifier.verify(message, &appended_signature),
                Err(CandidateError::SignatureLength { .. })
            ));
        }
    }

    #[test]
    fn oversized_messages_are_rejected_by_signer_and_verifier() {
        for algorithm in CandidateAlgorithm::ALL {
            let signer = signer(algorithm, 34);
            let verifier =
                CandidateVerifier::from_pinned_raw(algorithm, signer.public_key()).unwrap();
            let signature = signer.sign(b"bounded").unwrap();
            let oversized = vec![0; CANDIDATE_MAX_MESSAGE_BYTES + 1];
            let error = CandidateError::MessageTooLarge {
                actual: oversized.len(),
            };
            assert_eq!(signer.sign(&oversized), Err(error));
            assert_eq!(verifier.verify(&oversized, &signature), Err(error));
        }
    }

    #[test]
    fn cross_suite_keys_and_signatures_cannot_select_another_algorithm() {
        let first = signer(CandidateAlgorithm::MlDsa65, 35);
        let second = signer(CandidateAlgorithm::MlDsa87, 35);
        for (pinned, other) in [(&first, &second), (&second, &first)] {
            assert!(matches!(
                CandidateVerifier::from_pinned_raw(pinned.algorithm(), other.public_key()),
                Err(CandidateError::PublicKeyLength { .. })
            ));
            let verifier =
                CandidateVerifier::from_pinned_raw(pinned.algorithm(), pinned.public_key())
                    .unwrap();
            let signature = other.sign(b"same message, different suite").unwrap();
            assert!(matches!(
                verifier.verify(b"same message, different suite", &signature),
                Err(CandidateError::SignatureLength { .. })
            ));
        }
    }

    #[test]
    fn wrong_message_wrong_key_and_late_invalid_signatures_fail() {
        for algorithm in CandidateAlgorithm::ALL {
            let signer = signer(algorithm, 36);
            let other =
                CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new([37; 32])).unwrap();
            let verifier =
                CandidateVerifier::from_pinned_raw(algorithm, signer.public_key()).unwrap();
            let wrong_key =
                CandidateVerifier::from_pinned_raw(algorithm, other.public_key()).unwrap();
            let message = b"TRNM/Test/PQCandidate/v1\0purpose A";
            let mut signature = signer.sign(message).unwrap();
            assert_eq!(
                verifier.verify(b"TRNM/Test/PQCandidate/v1\0purpose B", &signature),
                Err(CandidateError::SignatureRejected)
            );
            assert_eq!(
                wrong_key.verify(message, &signature),
                Err(CandidateError::SignatureRejected)
            );
            // c_tilde is a fixed-size challenge string: this mutation preserves
            // signature syntax and reaches the arithmetic verification step.
            signature[0] ^= 1;
            assert_eq!(
                verifier.verify(message, &signature),
                Err(CandidateError::SignatureRejected)
            );
            assert_eq!(
                verifier.verify(message, &vec![0; algorithm.signature_bytes()]),
                Err(CandidateError::SignatureEncoding)
            );
        }
    }

    fn check_mode_separation<P: MlDsaParams>(algorithm: CandidateAlgorithm) {
        let raw = SigningKey::<P>::new_from_slice(&[38; 32]).unwrap();
        let public_key = raw.verifying_key().encode();
        let verifier = CandidateVerifier::from_pinned_raw(algorithm, &public_key).unwrap();
        let message = b"TRNM/Test/PQCandidate/v1\0exact message";
        let nonempty = raw
            .expanded_key()
            .sign_deterministic(message, b"different FIPS context")
            .unwrap();
        assert!(raw.verifying_key().verify_with_context(
            message,
            b"different FIPS context",
            &nonempty
        ));
        assert_eq!(
            verifier.verify(message, &nonempty.encode()),
            Err(CandidateError::SignatureRejected)
        );

        // A real HashML-DSA/SHA-512 signature is valid under its own framed
        // internal message, but must not be accepted by the Pure verifier.
        let digest = Sha512::digest(message);
        let sha512_oid = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ];
        let mut hash_message = vec![1, 0];
        hash_message.extend_from_slice(&sha512_oid);
        hash_message.extend_from_slice(&digest);
        let prehash = raw
            .expanded_key()
            .sign_internal(&[&hash_message], &Default::default());
        assert!(raw.verifying_key().verify_internal(&hash_message, &prehash));
        assert_eq!(
            verifier.verify(message, &prehash.encode()),
            Err(CandidateError::SignatureRejected)
        );

        let internal = raw
            .expanded_key()
            .sign_internal(&[message], &Default::default());
        assert!(raw.verifying_key().verify_internal(message, &internal));
        assert_eq!(
            verifier.verify(message, &internal.encode()),
            Err(CandidateError::SignatureRejected)
        );

        let digest_signature: Signature<P> = raw.try_sign(&digest).unwrap();
        assert_eq!(
            verifier.verify(message, &digest_signature.encode()),
            Err(CandidateError::SignatureRejected)
        );
    }

    #[test]
    fn mldsa65_rejects_context_prehash_and_raw_internal_modes() {
        check_mode_separation::<MlDsa65>(CandidateAlgorithm::MlDsa65);
    }

    #[test]
    fn mldsa87_rejects_context_prehash_and_raw_internal_modes() {
        check_mode_separation::<MlDsa87>(CandidateAlgorithm::MlDsa87);
    }
}
