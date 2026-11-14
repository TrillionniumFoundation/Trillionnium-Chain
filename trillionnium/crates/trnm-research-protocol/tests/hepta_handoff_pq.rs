//! Direct PQ cryptographic controls, not a claim of Hepta FinalUse integration.
use ed25519_dalek::SigningKey;
use std::cell::Cell;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use trnm_research_protocol::{
    Digest32, ExternalKey, HeptaArtifactAdmissionV1, HeptaHandoffError, PqHeptaAuthorityPinV2,
    PqHeptaAuthoritySetV2, PqHeptaHandoffError, SignedHeptaAdmissionV1, SignedHeptaAdmissionV2,
    MAX_HEPTA_PQ_HANDOFF_BYTES,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_100;
const DID: &str = "did:trnm:hepta-authority";

fn digest(byte: u8) -> Digest32 {
    [byte; 32]
}

fn admission() -> HeptaArtifactAdmissionV1 {
    HeptaArtifactAdmissionV1 {
        operation_id: ExternalKey::from_external_id("hepta.operation", "pq-handoff-001").unwrap(),
        artifact_digest: digest(0x80),
        owner_admission_digest: digest(0x81),
        family_digest: digest(0x82),
        source_digest_profile_digest: digest(0x83),
        parent_artifact_digest: None,
        generation: 1,
        withdrawal_scope_digest: digest(0x84),
        withdrawal_head_digest: digest(0x85),
        registry_head_digest: digest(0x86),
        evaluation_plan_digest: digest(0x87),
        task_scope_digest: digest(0x88),
        export_permission_digest: digest(0x89),
        payload_digest: digest(0x8a),
        payload_len: 4096,
        created_at_unix_s: NOW - 60,
        expires_at_unix_s: NOW + 60,
    }
}

fn signer_and_pin() -> (PqNativeSigningKey, PqHeptaAuthorityPinV2) {
    let seed = Zeroizing::new([0x47; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let signer = PqNativeSigningKey::from_owned_seed(seed, id).unwrap();
    let pin = PqHeptaAuthorityPinV2 {
        signer_did: DID.into(),
        key_id: id,
        generation: 7,
        spki,
        not_before_unix_s: NOW - 100,
        expires_at_unix_s: NOW + 100,
        revoked_at_unix_s: None,
    };
    (signer, pin)
}

fn signed(signer: &PqNativeSigningKey) -> SignedHeptaAdmissionV2 {
    SignedHeptaAdmissionV2::sign("trnm-pq-test".into(), DID.into(), 7, admission(), signer).unwrap()
}

#[test]
fn real_pq_signature_and_bounded_canonical_wire_round_trip() {
    let (signer, pin) = signer_and_pin();
    let original = signed(&signer);
    let encoded = original.encoded_bytes().unwrap();
    assert!(encoded.len() < MAX_HEPTA_PQ_HANDOFF_BYTES);
    let decoded = SignedHeptaAdmissionV2::decode_untrusted(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.encoded_bytes().unwrap(), encoded);
    let owner_pins = PqHeptaAuthoritySetV2::new(vec![pin]).unwrap();
    decoded
        .verify_for_context(&owner_pins, "trnm-pq-test", &admission(), NOW)
        .unwrap();
}

#[test]
fn no_classical_signature_or_algorithm_negotiation_is_accepted() {
    let (signer, pin) = signer_and_pin();
    let original = signed(&signer);
    let owner_pins = PqHeptaAuthoritySetV2::new(vec![pin]).unwrap();
    let classic = SignedHeptaAdmissionV1::sign(
        "trnm-pq-test".into(),
        DID.into(),
        admission(),
        &SigningKey::from_bytes(&[0x22; 32]),
    )
    .unwrap();
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&classic.canonical_bytes()).is_err());
    let mut wire = original.encoded_bytes().unwrap();
    wire[4] = 1; // legacy version
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&wire).is_err());
    wire[4] = 2;
    wire[5] = 0x01; // wrong algorithm
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&wire).is_err());
    let mut corrupt = original.clone();
    corrupt.signature[0] ^= 1;
    assert!(matches!(
        corrupt.verify_for_context(&owner_pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::InvalidSignature)
    ));
}

#[test]
fn pin_lifetime_generation_and_revocation_are_freshly_enforced() {
    let (signer, pin) = signer_and_pin();
    let original = signed(&signer);
    let mut old_generation = original.clone();
    old_generation.signer_generation = 6;
    let pins = PqHeptaAuthoritySetV2::new(vec![pin.clone()]).unwrap();
    assert!(matches!(
        old_generation.verify_for_context(&pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::UnauthorizedAuthority)
    ));
    let mut other_id = original.clone();
    other_id.signer_key_id[0] ^= 1;
    assert!(matches!(
        other_id.verify_for_context(&pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::UnauthorizedAuthority)
    ));
    let mut revoked = pin.clone();
    revoked.revoked_at_unix_s = Some(NOW);
    let revoked_pins = PqHeptaAuthoritySetV2::new(vec![revoked]).unwrap();
    assert!(matches!(
        original.verify_for_context(&revoked_pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::RevokedOrExpired)
    ));
    let mut expired = pin.clone();
    expired.expires_at_unix_s = NOW;
    let expired_pins = PqHeptaAuthoritySetV2::new(vec![expired]).unwrap();
    assert!(matches!(
        original.verify_for_context(&expired_pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::RevokedOrExpired)
    ));
    let future = NOW - 101;
    assert!(matches!(
        original.verify_for_context(&pins, "trnm-pq-test", &admission(), future),
        Err(PqHeptaHandoffError::Admission(_))
    ));
    let bad_duplicate = PqHeptaAuthoritySetV2::new(vec![pin.clone(), pin.clone()]);
    assert!(matches!(
        bad_duplicate,
        Err(PqHeptaHandoffError::InvalidPin)
    ));
    let mut wrong_spki_id = pin;
    wrong_spki_id.key_id[0] ^= 1;
    assert!(matches!(
        PqHeptaAuthoritySetV2::new(vec![wrong_spki_id]),
        Err(PqHeptaHandoffError::InvalidPin)
    ));
}

#[test]
fn one_pq_signing_key_cannot_claim_multiple_independent_dids() {
    let (signer, first) = signer_and_pin();
    let mut second = first.clone();
    second.signer_did = "did:trnm:independent-hepta-authority".into();
    second.generation = first.generation + 1;
    // Both records are individually well-formed; DID and generation differ.
    // Duplicate key material must still be refused by the pinned trust roster.
    for pins in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
    ] {
        assert!(matches!(
            PqHeptaAuthoritySetV2::new(pins),
            Err(PqHeptaHandoffError::InvalidPin)
        ));
    }

    // Positive control: a genuinely distinct ML-DSA public key on the second
    // DID remains valid, and the original real signature still verifies.
    let seed = Zeroizing::new([0x48; 32]);
    second.spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    second.key_id = ml_dsa_65_key_id_from_spki(&second.spki).unwrap();
    assert_ne!(second.key_id, first.key_id);
    let pins = PqHeptaAuthoritySetV2::new(vec![second, first]).unwrap();
    signed(&signer)
        .verify_for_context(&pins, "trnm-pq-test", &admission(), NOW)
        .unwrap();
}

#[test]
fn chain_and_fresh_hepta_owner_context_cannot_be_reused() {
    let (signer, pin) = signer_and_pin();
    let pins = PqHeptaAuthoritySetV2::new(vec![pin]).unwrap();
    let original = signed(&signer);
    assert!(matches!(
        original.verify_for_context(&pins, "other-chain", &admission(), NOW),
        Err(PqHeptaHandoffError::ContextMismatch("chain_id"))
    ));
    let mut latest = admission();
    latest.withdrawal_head_digest = digest(0x99);
    assert!(matches!(
        original.verify_for_context(&pins, "trnm-pq-test", &latest, NOW),
        Err(PqHeptaHandoffError::ContextMismatch("owner_admission"))
    ));
    let mut tampered = original.clone();
    tampered.admission.payload_digest = digest(0x91);
    assert!(matches!(
        tampered.verify_for_context(&pins, "trnm-pq-test", &tampered.admission, NOW),
        Err(PqHeptaHandoffError::InvalidSignature)
    ));
    assert!(original
        .verify_for_context(&pins, "trnm-pq-test", &admission(), NOW + 61,)
        .is_err());
}

#[test]
fn malformed_oversize_noncanonical_and_extra_bytes_fail_before_authorization() {
    let (signer, _pin) = signer_and_pin();
    let original = signed(&signer);
    let wire = original.encoded_bytes().unwrap();
    assert!(
        SignedHeptaAdmissionV2::decode_untrusted(&vec![0; MAX_HEPTA_PQ_HANDOFF_BYTES + 1],)
            .is_err()
    );
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&trailing).is_err());
    let mut reserved = wire.clone();
    reserved[6] = 1;
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&reserved).is_err());
    let mut impossible_len = wire.clone();
    impossible_len[8] = 255;
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&impossible_len).is_err());
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&wire[..wire.len() - 1]).is_err());
    let mut malformed_admission = wire;
    let admission_start =
        8 + 1 + original.chain_id.len() + 1 + original.signer_did.len() + 32 + 8 + 2;
    malformed_admission[admission_start] ^= 0x01; // canonical array header
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&malformed_admission).is_err());
}

// The three original 959 controls are adapted to the current THP2 wire and
// independent SPKI roster. They do not restore the earlier embedded-key wire
// and do not claim a production Hepta FinalUse consumer.
#[test]
fn trusted_context_ingress_rejects_mismatch_before_expensive_mldsa() {
    let (signer, pin) = signer_and_pin();
    let pins = PqHeptaAuthoritySetV2::new(vec![pin.clone()]).unwrap();
    let mut forged = signed(&signer);
    forged.signature[0] ^= 1;
    let wire = forged.encoded_bytes().unwrap();
    let called = Cell::new(0);
    let clock = || {
        called.set(called.get() + 1);
        NOW
    };
    assert!(matches!(
        SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &wire,
            &pins,
            "other-chain",
            &admission(),
            NOW,
            clock,
        ),
        Err(PqHeptaHandoffError::ContextMismatch("chain_id"))
    ));
    let mut other_owner = admission();
    other_owner.withdrawal_head_digest = digest(0x99);
    assert!(matches!(
        SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &wire,
            &pins,
            "trnm-pq-test",
            &other_owner,
            NOW,
            clock,
        ),
        Err(PqHeptaHandoffError::ContextMismatch("owner_admission"))
    ));
    let mut other_generation = pin;
    other_generation.generation += 1;
    let other_pins = PqHeptaAuthoritySetV2::new(vec![other_generation]).unwrap();
    assert!(matches!(
        SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &wire,
            &other_pins,
            "trnm-pq-test",
            &admission(),
            NOW,
            clock,
        ),
        Err(PqHeptaHandoffError::UnauthorizedAuthority)
    ));
    assert_eq!(called.get(), 0);

    // The current parser deliberately grants no authority. Correct context
    // then reaches the real signature check, which refuses the forged bytes
    // before the post-verification clock is called.
    assert!(SignedHeptaAdmissionV2::decode_untrusted(&wire).is_ok());
    assert!(matches!(
        SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &wire,
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW,
            clock,
        ),
        Err(PqHeptaHandoffError::InvalidSignature)
    ));
    assert!(matches!(
        forged.verify_for_context(&pins, "trnm-pq-test", &admission(), NOW),
        Err(PqHeptaHandoffError::InvalidSignature)
    ));
    assert_eq!(called.get(), 0);
}

#[test]
fn trusted_context_ingress_rechecks_clock_after_mldsa() {
    let (signer, pin) = signer_and_pin();
    let pins = PqHeptaAuthoritySetV2::new(vec![pin]).unwrap();
    let original = signed(&signer);
    let wire = original.encoded_bytes().unwrap();
    let called = Cell::new(0);
    let accepted = SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
        &wire,
        &pins,
        "trnm-pq-test",
        &admission(),
        NOW + 59,
        || {
            called.set(called.get() + 1);
            NOW + 60
        },
    )
    .unwrap();
    assert_eq!(accepted, original);
    assert_eq!(called.get(), 1); // admission expiry is inclusive
    assert!(matches!(
        original.verify_for_context_with_fresh_time(
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW + 59,
            || NOW + 61,
        ),
        Err(PqHeptaHandoffError::Admission(
            HeptaHandoffError::AdmissionExpired
        ))
    ));
    assert!(matches!(
        original.verify_for_context_with_fresh_time(
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW + 59,
            || NOW + 58,
        ),
        Err(PqHeptaHandoffError::TimeMovedBackwards)
    ));
    called.set(0);
    assert!(matches!(
        original.verify_for_context_with_fresh_time(
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW + 61,
            || {
                called.set(called.get() + 1);
                NOW
            },
        ),
        Err(PqHeptaHandoffError::Admission(
            HeptaHandoffError::AdmissionExpired
        ))
    ));
    assert_eq!(called.get(), 0); // an expired initial owner cannot be revived
}

#[test]
fn trusted_context_ingress_keeps_canonical_wire_bounds() {
    let (signer, pin) = signer_and_pin();
    let pins = PqHeptaAuthoritySetV2::new(vec![pin]).unwrap();
    let original = signed(&signer);
    let wire = original.encoded_bytes().unwrap();
    let mut trailing = wire.clone();
    trailing.push(0);
    let mut reserved = wire.clone();
    reserved[6] = 1;
    let called = Cell::new(0);
    for malformed in [
        vec![0; MAX_HEPTA_PQ_HANDOFF_BYTES + 1],
        trailing,
        reserved,
        wire[..wire.len() - 1].to_vec(),
    ] {
        assert!(SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &malformed,
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW,
            || {
                called.set(called.get() + 1);
                NOW
            },
        )
        .is_err());
    }
    assert_eq!(called.get(), 0);
    assert_eq!(
        SignedHeptaAdmissionV2::decode_for_context_with_fresh_time(
            &wire,
            &pins,
            "trnm-pq-test",
            &admission(),
            NOW,
            || NOW,
        )
        .unwrap(),
        original
    );
}

#[test]
fn postverification_pin_expiry_and_revocation_remain_exclusive() {
    let (signer, pin) = signer_and_pin();
    let original = signed(&signer);
    // The owner admission is live throughout these pin boundaries. Each
    // control reaches an actual valid ML-DSA verification at the initial time.
    for revoke in [false, true] {
        let mut selected = pin.clone();
        if revoke {
            selected.revoked_at_unix_s = Some(NOW + 1);
        } else {
            selected.expires_at_unix_s = NOW + 1;
        }
        let pins = PqHeptaAuthoritySetV2::new(vec![selected]).unwrap();
        let calls = Cell::new(0);
        original
            .verify_for_context_with_fresh_time(&pins, "trnm-pq-test", &admission(), NOW, || {
                calls.set(calls.get() + 1);
                NOW
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        for post in [NOW + 1, NOW + 2] {
            calls.set(0);
            assert!(matches!(
                original.verify_for_context_with_fresh_time(
                    &pins,
                    "trnm-pq-test",
                    &admission(),
                    NOW,
                    || {
                        calls.set(calls.get() + 1);
                        post
                    },
                ),
                Err(PqHeptaHandoffError::RevokedOrExpired)
            ));
            assert_eq!(calls.get(), 1);
        }
        calls.set(0);
        assert!(matches!(
            original.verify_for_context_with_fresh_time(
                &pins,
                "trnm-pq-test",
                &admission(),
                NOW + 1,
                || {
                    calls.set(calls.get() + 1);
                    NOW
                },
            ),
            Err(PqHeptaHandoffError::RevokedOrExpired)
        ));
        assert_eq!(calls.get(), 0);
    }
}
