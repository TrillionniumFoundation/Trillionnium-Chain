//! Complete CPQ1 candidate authentication with owner-pinned configuration/keys.
//! This is a bounded research entry point, not an activated transaction, CURRENT,
//! FinalUse, governance or recovery API. Existing ML-DSA-65 owners retain their
//! original wire and verifier. No input can choose an algorithm or fallback.

use crate::pq_candidate::{CandidateAlgorithm, CandidateError, CandidateVerifier};
use trnm_protocol::crypto_profile::{
    BoundCryptoProfile, CandidateEnvelope, CandidateVerificationBudget, CryptoProfile,
    CryptoProfileId, HashPurpose, ProfileError, CANDIDATE_MAX_SIGNERS,
};

#[derive(Debug)]
pub enum ProfileAuthenticationError {
    Policy(ProfileError),
    Signature(CandidateError),
}
impl std::fmt::Display for ProfileAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(f),
            Self::Signature(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ProfileAuthenticationError {}
impl From<ProfileError> for ProfileAuthenticationError {
    fn from(error: ProfileError) -> Self {
        Self::Policy(error)
    }
}
impl From<CandidateError> for ProfileAuthenticationError {
    fn from(error: CandidateError) -> Self {
        Self::Signature(error)
    }
}

/// Mathematical observation only. Its private constructor cannot create a
/// CurrentCryptoProfile; it says nothing about current roles or final-use state.
pub struct CandidateSignatureObservation<'a> {
    message: &'a [u8],
    crypto_profile_id: CryptoProfileId,
    signer_count: usize,
}
impl<'a> CandidateSignatureObservation<'a> {
    pub fn message(&self) -> &'a [u8] {
        self.message
    }
    pub fn crypto_profile_id(&self) -> CryptoProfileId {
        self.crypto_profile_id
    }
    pub fn signer_count(&self) -> usize {
        self.signer_count
    }
}

pub struct CandidateProfileVerifier {
    profile: BoundCryptoProfile,
    signer_ids: Vec<[u8; 64]>,
    verifiers: Vec<CandidateVerifier>,
}
impl CandidateProfileVerifier {
    /// Both inputs must be independently pinned by the caller. Key sorting
    /// produces the only canonical signer order and duplicate pins are refused.
    pub fn from_pinned_keys(
        profile: BoundCryptoProfile,
        pinned_keys: &[&[u8]],
    ) -> Result<Self, ProfileAuthenticationError> {
        let algorithm = match profile.profile() {
            CryptoProfile::CandidateMlDsa65V1 => CandidateAlgorithm::MlDsa65,
            CryptoProfile::CandidateMlDsa87V1 => CandidateAlgorithm::MlDsa87,
            CryptoProfile::LegacyMlDsa65V1 => return Err(ProfileError::CandidateOnly.into()),
        };
        if pinned_keys.is_empty() || pinned_keys.len() > CANDIDATE_MAX_SIGNERS {
            return Err(ProfileError::SignerSet.into());
        }
        let mut entries = Vec::with_capacity(pinned_keys.len());
        for key in pinned_keys {
            if key.len() != algorithm.public_key_bytes() {
                return Err(ProfileError::SignerSet.into());
            }
            entries.push((profile.commitment(HashPurpose::KeyIdentity, key)?, *key));
        }
        entries.sort_unstable_by_key(|(id, _)| *id);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ProfileError::SignerSet.into());
        }
        let signer_ids = entries.iter().map(|(id, _)| *id).collect();
        let verifiers = entries
            .into_iter()
            .map(|(_, key)| CandidateVerifier::from_pinned_raw(algorithm, key))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            profile,
            signer_ids,
            verifiers,
        })
    }
    pub fn profile(&self) -> &BoundCryptoProfile {
        &self.profile
    }
    pub fn signer_ids(&self) -> &[[u8; 64]] {
        &self.signer_ids
    }
    pub fn pinned_keys(&self) -> Vec<&[u8]> {
        self.verifiers
            .iter()
            .map(CandidateVerifier::public_key)
            .collect()
    }
    pub fn verify<'a>(
        &self,
        budget: &mut CandidateVerificationBudget,
        wire: &'a [u8],
        expected: &CandidateEnvelope<'_>,
    ) -> Result<CandidateSignatureObservation<'a>, ProfileAuthenticationError> {
        // All attempts, including malformed input and failures, use the shared
        // owner's aggregate reservation. No sub-signature resets the budget.
        budget.reserve(wire.len(), self.verifiers.len())?;
        if expected.signer_ids != self.signer_ids {
            return Err(ProfileError::SignerSet.into());
        }
        let pinned_keys = self.pinned_keys();
        let unverified = self
            .profile
            .check_candidate_wire(wire, expected, &pinned_keys)?;
        for (verifier, signature) in self.verifiers.iter().zip(unverified.signatures()) {
            verifier.verify(unverified.message(), signature)?;
        }
        Ok(CandidateSignatureObservation {
            message: unverified.message(),
            crypto_profile_id: self.profile.id(),
            signer_count: self.verifiers.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_candidate::CandidateSigningKey;
    use trnm_protocol::crypto_profile::{
        CryptoProfilePolicy, CryptoPurpose, ProfileBinding, ProfileScope,
    };
    use zeroize::Zeroizing;

    fn profile(p: CryptoProfile) -> BoundCryptoProfile {
        p.bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap()
    }
    fn context<'a>(ids: &'a [[u8; 64]], payload: &'a [u8]) -> CandidateEnvelope<'a> {
        CandidateEnvelope {
            purpose: CryptoPurpose::FinalUse,
            owner_generation: 1,
            key_epoch: 1,
            sequence: 1,
            valid_from_height: 1,
            valid_until_height: 10,
            signer_ids: ids,
            payload,
        }
    }
    #[test]
    fn real_complete_multisignatures_verify_in_both_candidates_but_cannot_activate() {
        for (p, algorithm) in [
            (
                CryptoProfile::CandidateMlDsa65V1,
                CandidateAlgorithm::MlDsa65,
            ),
            (
                CryptoProfile::CandidateMlDsa87V1,
                CandidateAlgorithm::MlDsa87,
            ),
        ] {
            let p = profile(p);
            let a =
                CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new([11; 32])).unwrap();
            let b =
                CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new([12; 32])).unwrap();
            let verifier = CandidateProfileVerifier::from_pinned_keys(
                p.clone(),
                &[a.public_key(), b.public_key()],
            )
            .unwrap();
            let expected = context(
                verifier.signer_ids(),
                b"complete release closure, owner and final-use request",
            );
            let message = p.candidate_message(&expected).unwrap();
            let keys = verifier.pinned_keys();
            let signatures: Vec<_> = keys
                .iter()
                .map(|key| {
                    if *key == a.public_key() {
                        a.sign(&message)
                    } else {
                        b.sign(&message)
                    }
                    .unwrap()
                })
                .collect();
            let signature_refs: Vec<_> = signatures.iter().map(Vec::as_slice).collect();
            let wire = p.candidate_wire(&expected, &keys, &signature_refs).unwrap();
            let mut budget = CandidateVerificationBudget::new();
            let observed = verifier.verify(&mut budget, &wire, &expected).unwrap();
            assert_eq!(observed.message(), message);
            assert_eq!(observed.signer_count(), 2);
            assert_eq!(observed.crypto_profile_id(), p.id());
            assert_eq!(budget.attempts(), 2);
            assert_eq!(budget.charged_bytes(), wire.len() as u64);
            let state = CryptoProfilePolicy::from_trusted_state(p.clone(), 5, 1, vec![]).unwrap();
            assert!(matches!(
                state.select_current(p.id()),
                Err(ProfileError::CandidateOnly)
            ));
            let mut bad = wire.clone();
            // First challenge byte of the last signature: same-size late reject.
            let challenge = bad.len() - algorithm.signature_bytes();
            bad[challenge] ^= 1;
            assert!(verifier.verify(&mut budget, &bad, &expected).is_err());
            assert_eq!(budget.attempts(), 4);
            let mut wrong_purpose = context(verifier.signer_ids(), expected.payload);
            wrong_purpose.purpose = CryptoPurpose::Current;
            assert!(verifier.verify(&mut budget, &wire, &wrong_purpose).is_err());
            let mut wrong_epoch = context(verifier.signer_ids(), expected.payload);
            wrong_epoch.key_epoch += 1;
            assert!(verifier.verify(&mut budget, &wire, &wrong_epoch).is_err());
            assert_eq!(budget.attempts(), 8);
            assert_eq!(budget.charged_bytes(), 4 * wire.len() as u64);
        }
    }
    #[test]
    fn key_parameters_duplicates_foreign_network_and_old_wire_are_refused() {
        let p65 = profile(CryptoProfile::CandidateMlDsa65V1);
        let p87 = profile(CryptoProfile::CandidateMlDsa87V1);
        let key = CandidateSigningKey::from_owned_seed(
            CandidateAlgorithm::MlDsa65,
            Zeroizing::new([7; 32]),
        )
        .unwrap();
        assert!(CandidateProfileVerifier::from_pinned_keys(p87, &[key.public_key()]).is_err());
        assert!(CandidateProfileVerifier::from_pinned_keys(
            p65.clone(),
            &[key.public_key(), key.public_key()]
        )
        .is_err());
        let verifier =
            CandidateProfileVerifier::from_pinned_keys(p65.clone(), &[key.public_key()]).unwrap();
        let expected = context(verifier.signer_ids(), b"bounded effect proposal");
        let signature = key
            .sign(&p65.candidate_message(&expected).unwrap())
            .unwrap();
        let wire = p65
            .candidate_wire(&expected, &[key.public_key()], &[&signature])
            .unwrap();
        let mut foreign_binding = *p65.binding();
        foreign_binding.network[0] ^= 1;
        let foreign_profile = CryptoProfile::CandidateMlDsa65V1
            .bind(foreign_binding)
            .unwrap();
        let foreign =
            CandidateProfileVerifier::from_pinned_keys(foreign_profile, &[key.public_key()])
                .unwrap();
        let foreign_expected = context(foreign.signer_ids(), expected.payload);
        let mut budget = CandidateVerificationBudget::new();
        assert!(foreign
            .verify(&mut budget, &wire, &foreign_expected)
            .is_err());
        assert!(verifier.verify(&mut budget, b"TPQ1", &expected).is_err());
        let mut appended = wire.clone();
        appended.push(0);
        assert!(verifier.verify(&mut budget, &appended, &expected).is_err());
        for _ in 3..64 {
            assert!(verifier.verify(&mut budget, b"bad", &expected).is_err());
        }
        assert_eq!(budget.attempts(), 64);
        assert!(matches!(
            verifier.verify(&mut budget, &wire, &expected),
            Err(ProfileAuthenticationError::Policy(ProfileError::Budget))
        ));
    }
}
