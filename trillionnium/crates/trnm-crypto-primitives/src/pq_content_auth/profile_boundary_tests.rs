//! An arbitrary decoded profile label can describe bytes, but cannot select
//! the independently pinned verifier or turn a legacy profile into CPQ1.
use super::*;
use crate::pq_candidate::{CandidateAlgorithm, CandidateSigningKey};
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentContextV1, ContentReadBudget},
    crypto_profile::{BoundCryptoProfile, CryptoProfile, ProfileBinding, ProfileScope},
};
use zeroize::Zeroizing;

fn profile(network: u8) -> BoundCryptoProfile {
    CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [network; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap()
}

fn assert_valid_signature_cannot_override_claim_profile(
    pinned: &BoundCryptoProfile,
    key: &CandidateSigningKey,
    verifier: &CandidateProfileVerifier,
    observed: &ObservedContentV1,
) {
    let payload = observed.claim().encode();
    let expected = CandidateEnvelope {
        purpose: CryptoPurpose::Release,
        owner_generation: 7,
        key_epoch: 3,
        sequence: 9,
        valid_from_height: 1,
        valid_until_height: 10,
        signer_ids: verifier.signer_ids(),
        payload: &payload,
    };
    let signature = key
        .sign(&pinned.candidate_message(&expected).unwrap())
        .unwrap();
    let wire = pinned
        .candidate_wire(&expected, &[key.public_key()], &[&signature])
        .unwrap();
    // This is a genuine signature over the entire maliciously labelled record.
    // Rejection below must therefore come from the full-content profile join.
    verifier
        .verify(&mut CandidateVerificationBudget::new(), &wire, &expected)
        .unwrap();
    let mut budget = CandidateVerificationBudget::new();
    assert!(matches!(
        verify_candidate_content(
            verifier,
            &mut budget,
            &wire,
            &expected,
            observed.claim(),
            observed,
        ),
        Err(ContentAuthenticationError::Binding)
    ));
    assert_eq!(budget.attempts(), 1);
    assert_eq!(budget.charged_bytes(), wire.len() as u64);
}

#[test]
fn decoded_legacy_or_unregistered_contexts_never_override_the_pinned_candidate_profile() {
    let pinned = profile(1);
    let key =
        CandidateSigningKey::from_owned_seed(CandidateAlgorithm::MlDsa65, Zeroizing::new([31; 32]))
            .unwrap();
    let verifier =
        CandidateProfileVerifier::from_pinned_keys(pinned.clone(), &[key.public_key()]).unwrap();
    let context = ContentContextV1::new(&pinned, ContentKind::ReleaseArtifact, [6; 64], 7).unwrap();
    let mut reads = ContentReadBudget::new(3, 1024).unwrap();
    let valid = observe_bytes(&context, &mut reads, b"complete actual bytes").unwrap();
    let legacy = CryptoProfile::LegacyMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 6,
            scope: ProfileScope::NativeAccounts,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap();
    assert!(ContentContextV1::new(&legacy, ContentKind::ReleaseArtifact, [6; 64], 7).is_err());
    assert!(
        CandidateProfileVerifier::from_pinned_keys(legacy.clone(), &[key.public_key()]).is_err()
    );
    for label in [*legacy.id().as_bytes(), [77; 64]] {
        let mut wire_claim = valid.claim().encode();
        wire_claim[4..68].copy_from_slice(&label);
        let decoded = ContentClaimV1::decode(&wire_claim).unwrap();
        // Decode is data parsing, not authenticated profile selection. Reading
        // under its label still produces only a byte observation.
        let observed =
            observe_bytes(decoded.context(), &mut reads, b"complete actual bytes").unwrap();
        assert_eq!(observed.claim().context().profile_id().as_bytes(), &label);
        assert_valid_signature_cannot_override_claim_profile(&pinned, &key, &verifier, &observed);
    }
}

#[test]
fn genuine_foreign_candidate_profile_cannot_cross_the_content_join_even_with_the_same_key() {
    let pinned = profile(1);
    let foreign = profile(9);
    let key =
        CandidateSigningKey::from_owned_seed(CandidateAlgorithm::MlDsa65, Zeroizing::new([32; 32]))
            .unwrap();
    let verifier =
        CandidateProfileVerifier::from_pinned_keys(pinned.clone(), &[key.public_key()]).unwrap();
    let context =
        ContentContextV1::new(&foreign, ContentKind::ReleaseArtifact, [6; 64], 7).unwrap();
    let mut reads = ContentReadBudget::new(1, 1024).unwrap();
    let observed = observe_bytes(&context, &mut reads, b"complete actual bytes").unwrap();
    assert_ne!(pinned.id(), observed.claim().context().profile_id());
    assert_valid_signature_cannot_override_claim_profile(&pinned, &key, &verifier, &observed);
}
