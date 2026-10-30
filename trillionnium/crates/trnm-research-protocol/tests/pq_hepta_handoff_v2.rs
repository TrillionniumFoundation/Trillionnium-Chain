use ed25519_dalek::SigningKey as Ed25519Key;
use ml_dsa::{
    KeyExport, KeyInit, Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey,
};
use trnm_research_protocol::*;

const CHAIN: &str = "trnm-dev-pq";
const DID: &str = "did:trnm:hepta-pq";

fn owner() -> HeptaArtifactAdmissionV1 {
    HeptaArtifactAdmissionV1 {
        operation_id: ExternalKey::from_external_id("hepta.operation", "pq-release").unwrap(),
        artifact_digest: [1; 32],
        owner_admission_digest: [2; 32],
        family_digest: [3; 32],
        source_digest_profile_digest: [4; 32],
        parent_artifact_digest: Some([5; 32]),
        generation: 2,
        withdrawal_scope_digest: [6; 32],
        withdrawal_head_digest: [7; 32],
        registry_head_digest: [8; 32],
        evaluation_plan_digest: [9; 32],
        task_scope_digest: [10; 32],
        export_permission_digest: [11; 32],
        payload_digest: [12; 32],
        payload_len: 4096,
        created_at_unix_s: 100,
        expires_at_unix_s: 200,
    }
}
fn key() -> SigningKey<MlDsa65> {
    SigningKey::<MlDsa65>::new_from_slice(&[42; 32]).unwrap()
}

#[test]
fn real_ml_dsa_sign_decode_and_current_context_succeed() {
    let sk = key();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let admission = owner();
    let signed =
        SignedPqHeptaAdmissionV2::sign(CHAIN.into(), DID.into(), admission.clone(), &sk).unwrap();
    assert_eq!(signed.signature.len(), ML_DSA_65_SIG_BYTES);
    let encoded = signed.canonical_bytes();
    assert!(encoded.len() < MAX_PQ_HEPTA_ENVELOPE_BYTES);
    let decoded = SignedPqHeptaAdmissionV2::from_canonical_bytes(&encoded).unwrap();
    decoded
        .verify_for_context(CHAIN, DID, &pk, &admission, 150)
        .unwrap();

    assert!(decoded
        .verify_for_context("other", DID, &pk, &admission, 150)
        .is_err());
    assert!(decoded
        .verify_for_context(CHAIN, "did:other:owner", &pk, &admission, 150)
        .is_err());
    assert!(decoded
        .verify_for_context(CHAIN, DID, &[0; ML_DSA_65_KEY_BYTES], &admission, 150)
        .is_err());
    assert!(decoded
        .verify_for_context(CHAIN, DID, &pk, &admission, 99)
        .is_err());
    assert!(decoded
        .verify_for_context(CHAIN, DID, &pk, &admission, 201)
        .is_err());
    for variant in 0..6 {
        let mut changed = admission.clone();
        match variant {
            0 => changed.withdrawal_head_digest[0] ^= 1,
            1 => changed.registry_head_digest[0] ^= 1,
            2 => changed.task_scope_digest[0] ^= 1,
            3 => changed.export_permission_digest[0] ^= 1,
            4 => changed.owner_admission_digest[0] ^= 1,
            _ => changed.payload_digest[0] ^= 1,
        }
        assert!(decoded
            .verify_for_context(CHAIN, DID, &pk, &changed, 150)
            .is_err());
    }
}

#[test]
fn classical_v1_and_unsigned_domain_are_not_a_pq_handoff() {
    let sk = key();
    let admission = owner();
    let v1 = SignedHeptaAdmissionV1::sign(
        CHAIN.into(),
        DID.into(),
        admission.clone(),
        &Ed25519Key::from_bytes(&[0x22; 32]),
    )
    .unwrap();
    assert!(SignedPqHeptaAdmissionV2::from_canonical_bytes(&v1.canonical_bytes()).is_err());

    let mut v2 =
        SignedPqHeptaAdmissionV2::sign(CHAIN.into(), DID.into(), admission.clone(), &sk).unwrap();
    let pk = sk.verifying_key().to_bytes().to_vec();
    let wrong_domain: Signature<MlDsa65> = sk.sign(&admission.canonical_bytes());
    v2.signature = wrong_domain.to_vec();
    assert!(v2
        .verify_for_context(CHAIN, DID, &pk, &admission, 150)
        .is_err());

    let mut v2 =
        SignedPqHeptaAdmissionV2::sign(CHAIN.into(), DID.into(), admission.clone(), &sk).unwrap();
    v2.signature[1] ^= 1;
    assert!(v2
        .verify_for_context(CHAIN, DID, &pk, &admission, 150)
        .is_err());
    let mut v2 = SignedPqHeptaAdmissionV2::sign(CHAIN.into(), DID.into(), admission, &sk).unwrap();
    v2.public_key[1] ^= 1;
    assert!(v2
        .verify_for_context(CHAIN, DID, &pk, &owner(), 150)
        .is_err());
}

#[test]
fn bounds_schema_and_trailing_wire_fail_closed() {
    let sk = key();
    let signed = SignedPqHeptaAdmissionV2::sign(CHAIN.into(), DID.into(), owner(), &sk).unwrap();
    let original = signed.canonical_bytes();
    assert!(matches!(
        SignedPqHeptaAdmissionV2::from_canonical_bytes(&vec![0; MAX_PQ_HEPTA_ENVELOPE_BYTES + 1]),
        Err(PqHeptaHandoffError::TooLarge)
    ));
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(SignedPqHeptaAdmissionV2::from_canonical_bytes(&trailing).is_err());
    let mut old_version = original.clone();
    old_version[1] = 1;
    assert!(matches!(
        SignedPqHeptaAdmissionV2::from_canonical_bytes(&old_version),
        Err(PqHeptaHandoffError::Canonical(
            CanonicalDecodeError::UnsupportedVersion(1)
        ))
    ));
    for n in [0, 1, 10, original.len() - 1] {
        assert!(SignedPqHeptaAdmissionV2::from_canonical_bytes(&original[..n]).is_err());
    }
    let mut invalid = signed;
    invalid.admission.payload_digest = [0; 32];
    assert!(invalid
        .verify_for_context(CHAIN, DID, &invalid.public_key, &owner(), 150)
        .is_err());
}
