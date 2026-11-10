use super::*;
use crate::cell::{
    version::tests::owner,
    version_content::tests::{captured, session},
    CellFileRoleV1,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn key() -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([93; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    (
        PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap(),
        CellPqKeyPinV2 {
            key_id,
            generation: 2,
            spki,
            not_before: 100,
            expires_at: 1000,
            revoked_at: None,
        },
    )
}
fn auth(content: &CellVersionContentV2, key: &PqNativeSigningKey) -> CellPqContentAuthorizationV4 {
    CellPqContentAuthorizationV4::sign(
        CellPqContentStatementV4 {
            network: [6; 32],
            parameters: [7; 32],
            content: content.commitment(),
            signer_key_id: key.public_key_id(),
            signer_spki_sha512: CellPqContentStatementV4::signer_commitment(key.public_spki()),
            generation: 2,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        key,
    )
    .unwrap()
}
fn expected<'a>(
    content: &CellVersionContentV2,
    pin: &'a CellPqKeyPinV2,
    model: &'a crate::cell::CellLoaderContextV1,
    environment: &'a crate::cell::CellLoaderContextV1,
) -> CellPqContentExpectationV4<'a> {
    CellPqContentExpectationV4 {
        authority: CellPqReleaseExpectationV2 {
            network: [6; 32],
            parameters: [7; 32],
            key: pin,
            sequence: 4,
            now: 300,
        },
        loader: CellVersionLoaderContextV1 {
            commitment: content.version().commitment(),
            model,
            environment,
        },
        content: content.commitment(),
    }
}

#[test]
fn cpv4_header_and_domain_match_independent_python_bytes() {
    let (_dir, _store, content) = captured();
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-version-content-v2.json"
    )))
    .unwrap();
    let statement = CellPqContentStatementV4 {
        network: [6; 32],
        parameters: [7; 32],
        content: content.commitment(),
        signer_key_id: [8; 32],
        signer_spki_sha512: [9; 64],
        generation: 2,
        sequence: 4,
        issued_at: 200,
        expires_at: 900,
        withdrawn: false,
    };
    assert_eq!(
        hex::encode(statement.encode().unwrap()),
        vector["cpv4_unsigned_header_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(Sha512::digest(statement.message().unwrap())),
        vector["cpv4_unsigned_message_sha512"].as_str().unwrap()
    );
}

#[test]
fn cpv4_signature_and_actual_bytes_are_both_required() {
    let (_dir, store, content) = captured();
    let (key, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = expected(&content, &pin, &model, &environment);
    let signed = auth(&content, &key);
    let wire = signed.encode().unwrap();
    assert_eq!(wire.len(), CELL_PQ_CONTENT_BYTES_V4);
    let decoded = CellPqContentAuthorizationV4::decode(&wire).unwrap();
    let verified = decoded
        .verify_cached_at(&content, &store, &expected, &mut session(1))
        .unwrap();
    assert_eq!(verified.content_at(&expected).unwrap(), &content);
    assert_eq!(verified.usage().reserved_payload_bytes, 4 * 32769);
    for index in [
        0,
        4,
        6,
        7,
        8,
        40,
        72,
        135,
        136,
        168,
        231,
        232,
        240,
        248,
        256,
        264,
        1000,
        wire.len() - 1,
    ] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        let mut budget = session(1);
        assert!(
            CellPqContentAuthorizationV4::decode(&changed)
                .and_then(|v| v.verify_cached_at(&content, &store, &expected, &mut budget))
                .is_err(),
            "byte {index}"
        );
        assert_eq!(
            budget.usage().reserved_payload_bytes,
            0,
            "unverified signature must not start payload I/O"
        );
    }
}

#[test]
fn cpv4_cannot_reuse_legacy_signature_or_legacy_complete_metadata_commitment() {
    let (_dir, store, content) = captured();
    let (key, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = expected(&content, &pin, &model, &environment);
    let signed = auth(&content, &key);
    assert!(super::super::CellPqVersionAuthorizationV3::decode(&signed.encode().unwrap()).is_err());
    let legacy = super::super::CellPqVersionAuthorizationV3::sign(
        super::super::CellPqVersionStatementV3 {
            network: [6; 32],
            parameters: [7; 32],
            version: content.commitment(),
            signer_key_id: key.public_key_id(),
            generation: 2,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        &key,
    )
    .unwrap();
    let mut substituted = signed.encode().unwrap();
    substituted[264..].copy_from_slice(&legacy.encode().unwrap()[200..]);
    assert!(CellPqContentAuthorizationV4::decode(&substituted)
        .unwrap()
        .verify_cached_at(&content, &store, &expected, &mut session(1))
        .is_err());
    let mut statement = signed.statement().clone();
    statement.content = content.version().commitment();
    let alias = CellPqContentAuthorizationV4::sign(statement, &key).unwrap();
    assert!(alias
        .verify_cached_at(&content, &store, &expected, &mut session(1))
        .is_err());
}

#[test]
fn cpv4_rechecks_complete_current_owner_pin_time_generation_and_sequence() {
    let (_dir, store, content) = captured();
    let (key, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let signed = auth(&content, &key);
    let proof = signed
        .verify_cached_at(
            &content,
            &store,
            &expected(&content, &pin, &model, &environment),
            &mut session(1),
        )
        .unwrap();
    let mut changed = pin.clone();
    changed.revoked_at = Some(300);
    assert!(proof
        .content_at(&expected(&content, &changed, &model, &environment))
        .is_err());
    changed = pin.clone();
    changed.generation += 1;
    assert!(proof
        .content_at(&expected(&content, &changed, &model, &environment))
        .is_err());
    let mut current = expected(&content, &pin, &model, &environment);
    current.authority.sequence += 1;
    assert!(proof.content_at(&current).is_err());
    current = expected(&content, &pin, &model, &environment);
    current.authority.now = 299;
    assert!(proof.content_at(&current).is_err());
    current.authority.now = 900;
    assert!(proof.content_at(&current).is_err());
    current = expected(&content, &pin, &model, &environment);
    current.content[63] ^= 1;
    assert!(proof.content_at(&current).is_err());
}

#[test]
fn cpv4_requires_full_spki_commitment_and_refuses_withdrawal_before_readback() {
    let (_dir, store, content) = captured();
    let (key, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = expected(&content, &pin, &model, &environment);
    let mut statement = auth(&content, &key).statement().clone();
    statement.signer_spki_sha512[63] ^= 1;
    assert!(CellPqContentAuthorizationV4::sign(statement.clone(), &key).is_err());
    statement.signer_spki_sha512 = CellPqContentStatementV4::signer_commitment(key.public_spki());
    statement.withdrawn = true;
    let withdrawn = CellPqContentAuthorizationV4::sign(statement, &key).unwrap();
    let mut budget = session(1);
    assert!(withdrawn
        .verify_cached_at(&content, &store, &expected, &mut budget)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 0);
}

#[test]
fn cpv4_retained_verifier_rechecks_signature_pin_and_current_observation() {
    let (_dir, store, content) = captured();
    let (key, pin) = key();
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let current = expected(&content, &pin, &model, &environment);
    let signed = auth(&content, &key);
    let proof = signed
        .verify_cached_at_with_pins(&content, &store, &current, &mut session(1), &keys)
        .unwrap();
    assert_eq!(proof.content_at(&current).unwrap(), &content);
    let mut bad = signed.clone();
    bad.signature[0] ^= 1;
    let mut budget = session(1);
    assert!(bad
        .verify_cached_at_with_pins(&content, &store, &current, &mut budget, &keys)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 0);
    bad = signed.clone();
    bad.statement.signer_spki_sha512[63] ^= 1;
    assert!(bad
        .verify_cached_at_with_pins(&content, &store, &current, &mut budget, &keys)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 0);
    let mut changed = pin.clone();
    changed.expires_at -= 1;
    let changed_view = expected(&content, &changed, &model, &environment);
    assert!(signed
        .verify_cached_at(&content, &store, &changed_view, &mut session(1))
        .is_ok());
    assert!(signed
        .verify_cached_at_with_pins(&content, &store, &changed_view, &mut budget, &keys)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 0);
    let mut next = expected(&content, &pin, &model, &environment);
    next.authority.sequence += 1;
    assert!(proof.content_at(&next).is_err());
    assert!(signed
        .verify_cached_at_with_pins(&content, &store, &current, &mut session(1), &keys.clone())
        .is_ok());
}

#[test]
fn cpv4_retained_verifier_keeps_complete_failed_readback_reservations_and_deadline() {
    let (dir, store, content) = captured();
    let (key, pin) = key();
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let current = expected(&content, &pin, &model, &environment);
    let signed = auth(&content, &key);
    let mut budget = session(2);
    let deadline = budget.deadline();
    signed
        .verify_cached_at_with_pins(&content, &store, &current, &mut budget, &keys)
        .unwrap();
    assert_eq!(budget.usage().attempted_scans, 1);
    assert_eq!(budget.usage().reserved_payload_bytes, 4 * 32769);
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    db.execute("DELETE FROM cell_chunks_v1", []).unwrap();
    assert!(signed
        .verify_cached_at_with_pins(&content, &store, &current, &mut budget, &keys)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 2);
    assert_eq!(budget.usage().reserved_payload_bytes, 8 * 32769);
    assert_eq!(budget.usage().reserved_chunks, 24);
    assert_eq!(budget.deadline(), deadline);
    assert!(signed
        .verify_cached_at_with_pins(&content, &store, &current, &mut budget, &keys)
        .is_err());
    assert_eq!(budget.usage().attempted_scans, 2);
    assert_eq!(budget.deadline(), deadline);
}
