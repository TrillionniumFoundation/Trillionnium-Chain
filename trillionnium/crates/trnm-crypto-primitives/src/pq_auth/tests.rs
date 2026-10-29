use super::*;
use sha2::{Digest, Sha256};
use trnm_protocol::pq_frame::payload_commitment;

fn signer(seed_byte: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed_byte; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let pin = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, pin).unwrap()
}

fn statement(e: &PqFrameExpectation<'_>) -> [u8; TPQ1_UNSIGNED_BYTES] {
    let mut out = [0; TPQ1_UNSIGNED_BYTES];
    out[..8].copy_from_slice(&[b'T', b'P', b'Q', b'1', 1, 0x65, e.purpose, 0]);
    out[8..40].copy_from_slice(&e.network);
    out[40..72].copy_from_slice(&e.owner_context);
    out[72..104].copy_from_slice(&e.signer_key_id);
    out[104..112].copy_from_slice(&e.owner_generation.to_be_bytes());
    out[112..120].copy_from_slice(&e.operation_sequence.to_be_bytes());
    out[120..128].copy_from_slice(&e.expires_at.to_be_bytes());
    out[128..176].copy_from_slice(&payload_commitment(e.payload).unwrap());
    out
}

#[test]
fn default_backend_authenticates_all_six_purposes_and_every_bound_field() {
    let signer = signer(7);
    let verifier =
        PqNativeVerifier::from_pinned_spki(signer.public_spki(), signer.public_key_id()).unwrap();
    for purpose in 1..=6 {
        let expected = PqFrameExpectation {
            purpose,
            network: [1; 32],
            owner_context: [2; 32],
            signer_key_id: signer.public_key_id(),
            owner_generation: 4,
            operation_sequence: 9,
            expires_at: 100,
            now: 99,
            payload: b"cell manifest",
        };
        let signed = signer
            .sign_statement(&statement(&expected), &expected)
            .unwrap();
        let observation = verifier.verify(&signed, &expected).unwrap();
        assert_eq!(*observation.signer_key_id(), expected.signer_key_id);
        assert_eq!(observation.authenticated_statement(), statement(&expected));
        for offset in 0..TPQ1_UNSIGNED_BYTES {
            let mut bad = signed;
            bad[offset] ^= 1;
            assert!(verifier.verify(&bad, &expected).is_err(), "field {offset}");
        }
        let mut expired = expected.clone();
        expired.now = 101;
        assert!(verifier.verify(&signed, &expired).is_err());
        assert!(signer
            .sign_statement(&statement(&expected), &expired)
            .is_err());
    }
}

#[test]
fn canonical_key_algorithm_parameters_lengths_and_independent_pin_are_required() {
    let signer = signer(11);
    let spki = signer.public_spki();
    for offset in 0..SPKI_PREFIX.len() {
        let mut bad = *spki;
        bad[offset] ^= 1;
        assert!(PqNativeVerifier::from_pinned_spki(&bad, signer.public_key_id()).is_err());
    }
    for len in [0, 22, ML_DSA_65_SPKI_BYTES - 1] {
        assert!(PqNativeVerifier::from_pinned_spki(&spki[..len], signer.public_key_id()).is_err());
    }
    let mut appended = spki.to_vec();
    appended.push(0);
    assert!(PqNativeVerifier::from_pinned_spki(&appended, signer.public_key_id()).is_err());
    assert!(PqNativeVerifier::from_pinned_spki(spki, [0; 32]).is_err());
    assert!(
        PqNativeSigningKey::from_owned_seed(Zeroizing::new([12; 32]), signer.public_key_id())
            .is_err()
    );
}

#[test]
fn message_domain_wrong_key_and_signature_malleation_never_fall_back() {
    let signer = signer(13);
    let verifier =
        PqNativeVerifier::from_pinned_spki(signer.public_spki(), signer.public_key_id()).unwrap();
    let message = b"TRNM/Test/PQ/v2\0actual authorization";
    let signature = signer.sign_exact_message(message).unwrap();
    assert_eq!(
        verifier
            .verify_exact_message(message, &signature)
            .unwrap()
            .authenticated_message(),
        message
    );
    assert!(verifier
        .verify_exact_message(b"TRNM/Test/PQ/v1\0actual authorization", &signature)
        .is_err());
    for offset in [0, 48, 1000, 3308] {
        let mut invalid = signature;
        invalid[offset] ^= 1;
        assert!(verifier.verify_exact_message(message, &invalid).is_err());
    }
    for invalid in [
        vec![],
        vec![0; 64],
        vec![0; 3308],
        vec![0; 3309],
        vec![0; 3310],
    ] {
        assert!(verifier.verify_exact_message(message, &invalid).is_err());
    }
    let other = signer_for_other_key();
    let wrong =
        PqNativeVerifier::from_pinned_spki(other.public_spki(), other.public_key_id()).unwrap();
    assert!(wrong.verify_exact_message(message, &signature).is_err());
}

fn signer_for_other_key() -> PqNativeSigningKey {
    signer(14)
}

#[test]
fn exact_message_limit_is_enforced_on_both_sides() {
    let signer = signer(15);
    let verifier =
        PqNativeVerifier::from_pinned_spki(signer.public_spki(), signer.public_key_id()).unwrap();
    let message = vec![9; PQ_MAX_MESSAGE_BYTES];
    let signature = signer.sign_exact_message(&message).unwrap();
    verifier.verify_exact_message(&message, &signature).unwrap();
    let too_long = vec![9; PQ_MAX_MESSAGE_BYTES + 1];
    assert!(signer.sign_exact_message(&too_long).is_err());
    assert!(verifier
        .verify_exact_message(&too_long, &signature)
        .is_err());
}

#[test]
fn contexts_and_internal_prehash_are_not_interchangeable_with_application_messages() {
    let key = SigningKey::<MlDsa65>::new_from_slice(&[16; 32]).unwrap();
    let spki = public_spki(&key);
    let verifier =
        PqNativeVerifier::from_pinned_spki(&spki, ml_dsa_65_key_id_from_spki(&spki).unwrap())
            .unwrap();
    let message = b"test domain";
    let nonempty = key
        .expanded_key()
        .sign_deterministic(message, b"not-empty")
        .unwrap();
    assert!(!key
        .verifying_key()
        .verify_with_context(message, b"", &nonempty));
    assert!(verifier
        .verify_exact_message(message, &nonempty.encode())
        .is_err());
    let internal = key
        .expanded_key()
        .sign_internal(&[message], &Default::default());
    assert!(verifier
        .verify_exact_message(message, &internal.encode())
        .is_err());
}

#[test]
fn pinned_independent_wycheproof_corpus_and_application_context_policy() {
    let bytes = include_bytes!("../../tests/fixtures/wycheproof/mldsa_65_verify_test.json");
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034"
    );
    let corpus: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(corpus["numberOfTests"], 210);
    assert_eq!(corpus["algorithm"], "ML-DSA-65");
    let mut count = 0;
    let mut valid = 0;
    let mut invalid = 0;
    for group in corpus["testGroups"].as_array().unwrap() {
        let spki = hex::decode(group["publicKeyDer"].as_str().unwrap()).unwrap();
        let verifier = ml_dsa_65_key_id_from_spki(&spki)
            .ok()
            .and_then(|pin| PqNativeVerifier::from_pinned_spki(&spki, pin).ok());
        for case in group["tests"].as_array().unwrap() {
            count += 1;
            let message = hex::decode(case["msg"].as_str().unwrap()).unwrap();
            let sig = hex::decode(case["sig"].as_str().unwrap()).unwrap();
            let context = hex::decode(case["ctx"].as_str().unwrap_or("")).unwrap();
            let expect = match case["result"].as_str().unwrap() {
                "valid" => {
                    valid += 1;
                    true
                }
                "invalid" => {
                    invalid += 1;
                    false
                }
                value => panic!("unhandled independent verdict: {value}"),
            };
            // Exercise the independent corpus's specified FIPS context, then
            // also exercise this application's empty-context-only boundary.
            let actual = verifier.as_ref().is_some_and(|v| {
                Signature::<MlDsa65>::try_from(sig.as_slice())
                    .ok()
                    .is_some_and(|s| v.key.verify_with_context(&message, &context, &s))
            });
            assert_eq!(actual, expect, "FIPS vector {}", case["tcId"]);
            let application = verifier
                .as_ref()
                .is_some_and(|v| v.verify_exact_message(&message, &sig).is_ok());
            assert_eq!(
                application,
                expect && context.is_empty(),
                "application vector {}",
                case["tcId"]
            );
        }
    }
    assert_eq!((count, valid, invalid), (210, 79, 131));
}
