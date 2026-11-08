use super::*;
use crate::pq_candidate::{CandidateAlgorithm, CandidateSigningKey};
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentContextV1, ContentReadBudget},
    crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope},
};
use zeroize::Zeroizing;

#[test]
fn actual_mldsa_signatures_bind_complete_content_and_refuse_downgrade() {
    for (profile, algorithm) in [
        (
            CryptoProfile::CandidateMlDsa65V1,
            CandidateAlgorithm::MlDsa65,
        ),
        (
            CryptoProfile::CandidateMlDsa87V1,
            CandidateAlgorithm::MlDsa87,
        ),
    ] {
        let p = profile
            .bind(ProfileBinding {
                network: [1; 32],
                parameters: [2; 32],
                genesis: [3; 32],
                protocol_version: 1,
                scope: ProfileScope::WholeSystemCandidate,
                activation_height: 0,
                retirement_height: None,
            })
            .unwrap();
        let key =
            CandidateSigningKey::from_owned_seed(algorithm, Zeroizing::new([11; 32])).unwrap();
        let verifier =
            CandidateProfileVerifier::from_pinned_keys(p.clone(), &[key.public_key()]).unwrap();
        for (kind, purpose) in [
            (ContentKind::StateSnapshot, CryptoPurpose::Recovery),
            (ContentKind::ReleaseArtifact, CryptoPurpose::Release),
            (ContentKind::ModelManifest, CryptoPurpose::Release),
            (ContentKind::ModelPayload, CryptoPurpose::Release),
            (ContentKind::MigrationCheckpoint, CryptoPurpose::Migration),
        ] {
            let context = ContentContextV1::new(&p, kind, [6; 64], 7).unwrap();
            let mut reads = ContentReadBudget::new(4, 1024).unwrap();
            let observed = observe_bytes(&context, &mut reads, b"complete actual source").unwrap();
            let payload = observed.claim().encode();
            let mut expected = CandidateEnvelope {
                purpose,
                owner_generation: 7,
                key_epoch: 3,
                sequence: 9,
                valid_from_height: 1,
                valid_until_height: 10,
                signer_ids: verifier.signer_ids(),
                payload: &payload,
            };
            let message = p.candidate_message(&expected).unwrap();
            let signature = key.sign(&message).unwrap();
            let wire = p
                .candidate_wire(&expected, &[key.public_key()], &[&signature])
                .unwrap();
            let mut budget = CandidateVerificationBudget::new();
            let result = verify_candidate_content(
                &verifier,
                &mut budget,
                &wire,
                &expected,
                observed.claim(),
                &observed,
            )
            .unwrap();
            assert_eq!(result.claim(), observed.claim());
            assert_eq!(result.signature().message(), message);
            let bad = observe_bytes(&context, &mut reads, b"complete altered source").unwrap();
            assert!(verify_candidate_content(
                &verifier,
                &mut budget,
                &wire,
                &expected,
                observed.claim(),
                &bad
            )
            .is_err());
            expected.owner_generation += 1;
            assert!(verify_candidate_content(
                &verifier,
                &mut budget,
                &wire,
                &expected,
                observed.claim(),
                &observed
            )
            .is_err());
            expected.owner_generation -= 1;
            expected.purpose = CryptoPurpose::FinalUse;
            assert!(verify_candidate_content(
                &verifier,
                &mut budget,
                &wire,
                &expected,
                observed.claim(),
                &observed
            )
            .is_err());
            expected.purpose = purpose;
            expected.payload = observed.claim().digest();
            // Even a valid signature over just the digest is not the CCH1 record.
            let weak_message = p.candidate_message(&expected).unwrap();
            let weak_signature = key.sign(&weak_message).unwrap();
            let weak_wire = p
                .candidate_wire(&expected, &[key.public_key()], &[&weak_signature])
                .unwrap();
            assert!(verify_candidate_content(
                &verifier,
                &mut budget,
                &weak_wire,
                &expected,
                observed.claim(),
                &observed
            )
            .is_err());
            assert_eq!(budget.attempts(), 5);
        }
    }
}
