use super::*;
use crate::cell::{
    version::tests::{fixture, owner},
    CellFileRoleV1, CellLoaderContextV1, CellModelReleaseRootV1, CellReleaseClosureV1,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn key() -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([72; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let key = PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap();
    (
        key,
        CellPqKeyPinV2 {
            key_id,
            generation: 1,
            spki,
            not_before: 100,
            expires_at: 1000,
            revoked_at: None,
        },
    )
}

fn expected<'a>(
    version: &CellVersionManifestV1,
    pin: &'a CellPqKeyPinV2,
    model: &'a CellLoaderContextV1,
    environment: &'a CellLoaderContextV1,
) -> CellPqVersionExpectationV3<'a> {
    CellPqVersionExpectationV3 {
        authority: CellPqReleaseExpectationV2 {
            network: [6; 32],
            parameters: [7; 32],
            key: pin,
            sequence: 4,
            now: 300,
        },
        loader: CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model,
            environment,
        },
    }
}

fn auth(version: &CellVersionManifestV1, key: &PqNativeSigningKey) -> CellPqVersionAuthorizationV3 {
    CellPqVersionAuthorizationV3::sign(
        CellPqVersionStatementV3 {
            network: [6; 32],
            parameters: [7; 32],
            version: version.commitment(),
            signer_key_id: key.public_key_id(),
            generation: 1,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        key,
    )
    .unwrap()
}

#[test]
fn cpv3_signs_complete_version_and_rejects_statement_signature_mutations() {
    let (_dir, _store, version) = fixture();
    let (key, pin) = key();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let expected = expected(&version, &pin, &model, &environment);
    let auth = auth(&version, &key);
    let wire = auth.encode().unwrap();
    assert_eq!(wire.len(), CELL_PQ_VERSION_BYTES_V3);
    assert_eq!(
        auth.verify_at(&version, &expected)
            .unwrap()
            .version_at(&expected)
            .unwrap(),
        &version
    );
    for index in (0..200).chain([200, 1000, wire.len() - 1]) {
        let mut corrupt = wire.clone();
        corrupt[index] ^= 1;
        assert!(
            CellPqVersionAuthorizationV3::decode(&corrupt)
                .and_then(|a| a.verify_at(&version, &expected))
                .is_err(),
            "byte {index}"
        );
    }
}

#[test]
fn cpv3_cannot_reuse_a_signature_for_same_files_with_other_dependency_edges() {
    let (_dir, _store, version) = fixture();
    let (key, pin) = key();
    let old = version.model().closure();
    let mut files = old.files().to_vec();
    files[0].dependencies.clear();
    let changed = CellReleaseClosureV1::new(
        old.release().context().clone(),
        old.selected_generation(),
        old.loader_profile(),
        vec![0, 1],
        files,
    )
    .unwrap();
    assert_eq!(old.release().id(), changed.release().id());
    let different = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(changed, vec![]).unwrap(),
        version.environment().clone(),
        version.manifests().to_vec(),
    )
    .unwrap();
    let model = owner(different.model().closure(), CellFileRoleV1::Base);
    let environment = owner(different.environment(), CellFileRoleV1::Configuration);
    assert!(auth(&version, &key)
        .verify_at(
            &different,
            &expected(&different, &pin, &model, &environment)
        )
        .is_err());
}

#[test]
fn cpv3_cached_publisher_observation_rechecks_current_owner_not_only_time() {
    let (_dir, _store, version) = fixture();
    let (key, pin) = key();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let authorization = auth(&version, &key);
    let proof = authorization
        .verify_at(&version, &expected(&version, &pin, &model, &environment))
        .unwrap();
    let mut revoked = pin.clone();
    revoked.revoked_at = Some(300);
    assert!(proof
        .version_at(&expected(&version, &revoked, &model, &environment))
        .is_err());
    let mut rotated = pin.clone();
    rotated.generation += 1;
    assert!(proof
        .version_at(&expected(&version, &rotated, &model, &environment))
        .is_err());
    let mut current = expected(&version, &pin, &model, &environment);
    current.authority.sequence += 1;
    assert!(proof.version_at(&current).is_err());
    current = expected(&version, &pin, &model, &environment);
    current.loader.commitment[63] ^= 1;
    assert!(proof.version_at(&current).is_err());
    current = expected(&version, &pin, &model, &environment);
    current.authority.now = 299;
    assert!(proof.version_at(&current).is_err());
    current.authority.now = 900;
    assert!(proof.version_at(&current).is_err());
    let mut smaller = model.clone();
    smaller.max_chunks = 5;
    assert!(proof
        .version_at(&expected(&version, &pin, &smaller, &environment))
        .is_err());
    let mut stale_loader = model.clone();
    stale_loader.selected_generation += 1;
    assert!(proof
        .version_at(&expected(&version, &pin, &stale_loader, &environment))
        .is_err());
}

#[test]
fn cpv3_withdrawal_expiry_and_legacy_profile_have_no_fallback() {
    let (_dir, _store, version) = fixture();
    let (key, pin) = key();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let mut statement = auth(&version, &key).statement().clone();
    statement.withdrawn = true;
    let withdrawn = CellPqVersionAuthorizationV3::sign(statement, &key).unwrap();
    assert!(withdrawn
        .verify_at(&version, &expected(&version, &pin, &model, &environment))
        .is_err());
    let auth = auth(&version, &key);
    let mut expired = expected(&version, &pin, &model, &environment);
    expired.authority.now = 900;
    assert!(auth.verify_at(&version, &expired).is_err());
    let mut legacy = auth.encode().unwrap();
    legacy[..6].copy_from_slice(&[b'C', b'P', b'R', b'2', 2, 0x65]);
    assert!(CellPqVersionAuthorizationV3::decode(&legacy).is_err());
    assert!(
        crate::cell::pq::CellPqReleaseAuthorizationV2::decode(&auth.encode().unwrap()).is_err()
    );
}

#[test]
fn cpv3_retained_verifier_rechecks_signature_and_complete_authority_pin() {
    let (_dir, _store, version) = fixture();
    let (key, pin) = key();
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    let current = expected(&version, &pin, &model, &environment);
    let authorization = auth(&version, &key);
    let proof = authorization
        .verify_at_with_pins(&version, &current, &keys)
        .unwrap();
    assert_eq!(proof.version_at(&current).unwrap(), &version);
    let mut bad = authorization.clone();
    bad.signature[0] ^= 1;
    assert!(bad.verify_at_with_pins(&version, &current, &keys).is_err());
    let mut changed = pin.clone();
    changed.revoked_at = Some(800);
    let changed_view = expected(&version, &changed, &model, &environment);
    assert!(authorization.verify_at(&version, &changed_view).is_ok());
    assert!(authorization
        .verify_at_with_pins(&version, &changed_view, &keys)
        .is_err());
    let mut next = expected(&version, &pin, &model, &environment);
    next.authority.sequence += 1;
    assert!(proof.version_at(&next).is_err());
    assert!(authorization
        .verify_at_with_pins(&version, &current, &keys.clone())
        .is_ok());
}
