#![cfg(feature = "pq-native-openssl")]
//! Real native EVP operations. Known disposable seeds are test inputs only.
use openssl::pkey::{KeyType, PKey, Private};
use openssl::sign::{Signer, Verifier};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::{
    ml_dsa_65_key_id_from_spki, payload_commitment, preflight_unverified_with_spki,
    PqFrameExpectation, ML_DSA_65_SIGNATURE_BYTES, TPQ1_SIGNED_BYTES, TPQ1_UNSIGNED_BYTES,
};

fn key(seed: u8) -> PKey<Private> {
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32])
        .expect("actual ML-DSA-65 provider required; no stub/skip fallback")
}

fn expectation(key: &PKey<Private>, purpose: u8) -> PqFrameExpectation<'static> {
    PqFrameExpectation {
        purpose,
        network: [1; 32],
        owner_context: [2; 32],
        signer_key_id: ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap(),
        owner_generation: 7,
        operation_sequence: 19,
        expires_at: 4000,
        now: 3999,
        payload: b"public Cell release manifest hash and consent",
    }
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
fn all_six_purposes_use_actual_native_sign_and_verify() {
    let owned = key(7);
    let spki = owned.public_key_to_der().unwrap();
    for purpose in 1..=6 {
        let e = expectation(&owned, purpose);
        let signer = PqNativeSigningKey::from_owned_key(owned.clone(), e.signer_key_id).unwrap();
        let frame = signer.sign_statement(&statement(&e), &e).unwrap();
        assert_eq!(frame.len(), 3487);
        let verifier = PqNativeVerifier::from_pinned_spki(&spki, e.signer_key_id).unwrap();
        let observed = verifier.verify(&frame, &e).unwrap();
        assert_eq!(observed.authenticated_statement(), statement(&e));
        assert_eq!(*observed.signer_key_id(), e.signer_key_id);
        let mut other_purpose = e.clone();
        other_purpose.purpose = purpose % 6 + 1;
        assert!(verifier.verify(&frame, &other_purpose).is_err());
    }
}

#[test]
fn syntactically_valid_fake_signature_never_becomes_verified() {
    let owned = key(8);
    let spki = owned.public_key_to_der().unwrap();
    let e = expectation(&owned, 4);
    let signer = PqNativeSigningKey::from_owned_key(owned, e.signer_key_id).unwrap();
    let good = signer.sign_statement(&statement(&e), &e).unwrap();
    let verifier = PqNativeVerifier::from_pinned_spki(&spki, e.signer_key_id).unwrap();
    for offset in [178, 179, TPQ1_SIGNED_BYTES - 1] {
        let mut forged = good;
        forged[offset] ^= 1;
        assert!(preflight_unverified_with_spki(&forged, &e, &spki).is_ok());
        assert!(verifier.verify(&forged, &e).is_err());
    }
    let mut forged = good;
    forged[178..].fill(0);
    assert!(preflight_unverified_with_spki(&forged, &e, &spki).is_ok());
    assert!(verifier.verify(&forged, &e).is_err());
    assert!(verifier.verify(&good[..3486], &e).is_err());
}

#[test]
fn all_signed_bytes_context_payload_lifetime_and_pin_fail_closed() {
    let owned = key(9);
    let spki = owned.public_key_to_der().unwrap();
    let e = expectation(&owned, 4);
    let signer = PqNativeSigningKey::from_owned_key(owned, e.signer_key_id).unwrap();
    let good = signer.sign_statement(&statement(&e), &e).unwrap();
    let verifier = PqNativeVerifier::from_pinned_spki(&spki, e.signer_key_id).unwrap();
    for offset in 0..TPQ1_UNSIGNED_BYTES {
        let mut bad = good;
        bad[offset] ^= 1;
        assert!(verifier.verify(&bad, &e).is_err(), "signed byte {offset}");
    }
    for field in 0..8 {
        let mut wrong = e.clone();
        match field {
            0 => wrong.network[0] ^= 1,
            1 => wrong.owner_context[0] ^= 1,
            2 => wrong.signer_key_id[0] ^= 1,
            3 => wrong.owner_generation += 1,
            4 => wrong.operation_sequence += 1,
            5 => wrong.expires_at += 1,
            6 => wrong.now = 4001,
            _ => wrong.payload = b"different model bytes",
        }
        assert!(verifier.verify(&good, &wrong).is_err());
        assert!(signer.sign_statement(&statement(&e), &wrong).is_err());
    }
    let other_spki = key(10).public_key_to_der().unwrap();
    assert!(PqNativeVerifier::from_pinned_spki(&other_spki, e.signer_key_id).is_err());
    let other_id = ml_dsa_65_key_id_from_spki(&other_spki).unwrap();
    let other = PqNativeVerifier::from_pinned_spki(&other_spki, other_id).unwrap();
    assert!(other.verify(&good, &e).is_err());
}

#[test]
fn canonical_spki_and_classical_downgrade_refuse_without_fallback() {
    let owned = key(11);
    let spki = owned.public_key_to_der().unwrap();
    let e = expectation(&owned, 4);
    for offset in 0..22 {
        let mut bad = spki.clone();
        bad[offset] ^= 1;
        assert!(PqNativeVerifier::from_pinned_spki(&bad, e.signer_key_id).is_err());
    }
    let mut trailing = spki.clone();
    trailing.push(0);
    assert!(PqNativeVerifier::from_pinned_spki(&trailing, e.signer_key_id).is_err());
    let ed = PKey::generate_ed25519().unwrap();
    assert!(
        PqNativeVerifier::from_pinned_spki(&ed.public_key_to_der().unwrap(), e.signer_key_id)
            .is_err()
    );
    assert!(PqNativeSigningKey::from_owned_key(ed, e.signer_key_id).is_err());
    let signer = PqNativeSigningKey::from_owned_key(owned, e.signer_key_id).unwrap();
    let mut wrong = statement(&e);
    wrong[5] = 0x19;
    assert!(signer.sign_statement(&wrong, &e).is_err());
}

#[test]
fn adapter_and_direct_evp_interoperate_on_the_same_native_frame() {
    let owned = key(12);
    let spki = owned.public_key_to_der().unwrap();
    let e = expectation(&owned, 2);
    let message = statement(&e);
    let mut frame = [0; TPQ1_SIGNED_BYTES];
    frame[..176].copy_from_slice(&message);
    frame[176..178].copy_from_slice(&(ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
    let mut direct = Signer::new_without_digest(&owned).unwrap();
    assert_eq!(
        direct.sign_oneshot(&mut frame[178..], &message).unwrap(),
        3309
    );
    let native = PqNativeVerifier::from_pinned_spki(&spki, e.signer_key_id).unwrap();
    native.verify(&frame, &e).unwrap();
    let signer = PqNativeSigningKey::from_owned_key(owned.clone(), e.signer_key_id).unwrap();
    let signed = signer.sign_statement(&message, &e).unwrap();
    let mut direct = Verifier::new_without_digest(&owned).unwrap();
    assert!(direct.verify_oneshot(&signed[178..], &message).unwrap());
}
