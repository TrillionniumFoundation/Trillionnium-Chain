use super::*;
use trnm_protocol::pq_frame::{ml_dsa_65_key_id_from_spki, TPQ1_UNSIGNED_BYTES};

const SPKI: &[u8] = include_bytes!("../tests/fixtures/pq/openssl_mldsa65_spki.der");
const FRAME: &[u8] = include_bytes!("../tests/fixtures/pq/openssl_tpq1_frame.bin");
const PAYLOAD: &[u8] = b"public Cell release manifest hash and consent";

fn expectation() -> PqFrameExpectation<'static> {
    PqFrameExpectation {
        purpose: 4,
        network: [1; 32],
        owner_context: [2; 32],
        signer_key_id: ml_dsa_65_key_id_from_spki(SPKI).unwrap(),
        owner_generation: 7,
        operation_sequence: 19,
        expires_at: 4000,
        now: 3999,
        payload: PAYLOAD,
    }
}

#[test]
fn independently_signed_openssl_frame_passes_native_verification() {
    let expected = expectation();
    let checked = verify_tpq1(FRAME, &expected, SPKI).unwrap();
    assert_eq!(checked.statement(), &FRAME[..TPQ1_UNSIGNED_BYTES]);
    assert_eq!(checked.signer_key_id(), &expected.signer_key_id);
}

#[test]
fn every_statement_byte_and_signature_region_tamper_is_rejected() {
    let expected = expectation();
    for index in (0..TPQ1_UNSIGNED_BYTES).chain([176, 177, 178, 179, 1000, FRAME.len() - 1]) {
        let mut altered = FRAME.to_vec();
        altered[index] ^= 1;
        assert!(
            verify_tpq1(&altered, &expected, SPKI).is_err(),
            "byte {index}"
        );
    }
    let mut zeros = FRAME.to_vec();
    zeros[178..].fill(0);
    assert!(verify_tpq1(&zeros, &expected, SPKI).is_err());
}

#[test]
fn caller_context_and_key_substitution_do_not_authenticate() {
    let mut expected = expectation();
    expected.now = 4001;
    assert_eq!(
        verify_tpq1(FRAME, &expected, SPKI).unwrap_err(),
        PqAuthError::Frame(PqFrameError::Expired)
    );
    expected = expectation();
    expected.payload = b"different release";
    assert!(verify_tpq1(FRAME, &expected, SPKI).is_err());
    expected = expectation();
    expected.operation_sequence += 1;
    assert!(verify_tpq1(FRAME, &expected, SPKI).is_err());
    let mut replacement = SPKI.to_vec();
    replacement[22] ^= 1;
    let mut altered_frame = FRAME.to_vec();
    expected = expectation();
    expected.signer_key_id = ml_dsa_65_key_id_from_spki(&replacement).unwrap();
    altered_frame[72..104].copy_from_slice(&expected.signer_key_id);
    assert!(verify_tpq1(&altered_frame, &expected, &replacement).is_err());
}

#[test]
fn malformed_der_classical_signature_and_context_downgrade_reject() {
    let expected = expectation();
    for index in [0, 3, 15, 20, 21] {
        let mut key = SPKI.to_vec();
        key[index] ^= 1;
        assert!(verify_tpq1(FRAME, &expected, &key).is_err());
    }
    let mut frame = FRAME.to_vec();
    frame[5] = 0x19;
    assert!(verify_tpq1(&frame, &expected, SPKI).is_err());
    assert!(verify_ml_dsa_65(&SPKI[22..], &FRAME[..176], &[], &[0; 64]).is_err());
    assert!(verify_ml_dsa_65(&SPKI[22..], &FRAME[..176], b"not-empty", &FRAME[178..]).is_err());
}

#[test]
fn complete_pinned_wycheproof_corpus_including_duplicate_hints() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/pq/mldsa_65_verify_test.json"
    ))
    .unwrap();
    let mut tested = 0;
    let mut duplicate_hint_rejections = 0;
    for group in corpus["testGroups"].as_array().unwrap() {
        let pk = hex::decode(group["publicKey"].as_str().unwrap()).unwrap();
        for case in group["tests"].as_array().unwrap() {
            let message = hex::decode(case["msg"].as_str().unwrap()).unwrap();
            let sig = hex::decode(case["sig"].as_str().unwrap()).unwrap();
            let context = hex::decode(case["ctx"].as_str().unwrap_or("")).unwrap();
            let accepted = verify_ml_dsa_65(&pk, &message, &context, &sig).is_ok();
            let valid = case["result"] == "valid";
            assert_eq!(
                accepted, valid,
                "Wycheproof {}: {}",
                case["tcId"], case["comment"]
            );
            if case["comment"].as_str().unwrap().contains("repeated hint") {
                assert!(!accepted);
                duplicate_hint_rejections += 1;
            }
            tested += 1;
        }
    }
    assert_eq!(tested, corpus["numberOfTests"].as_u64().unwrap());
    assert!(duplicate_hint_rejections > 0);
}
