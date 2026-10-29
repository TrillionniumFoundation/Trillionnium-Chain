use super::*;
use zeroize::Zeroizing;

fn fixture() -> (
    PqNativeSigningKey,
    CellPqKeyPinV2,
    CellReleaseManifestV1,
    CellPqReleaseAuthorizationV2,
) {
    let seed = Zeroizing::new([71; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let key = PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap();
    let pin = CellPqKeyPinV2 {
        key_id,
        spki,
        generation: 1,
        not_before: 100,
        expires_at: 1000,
        revoked_at: None,
    };
    let context = crate::cell::CellContextV1 {
        family: "pq-release".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let release = CellReleaseManifestV1::new(context, vec![[9; 32], [8; 32]]).unwrap();
    let auth = CellPqReleaseAuthorizationV2::sign(
        CellPqReleaseStatementV2 {
            network: [6; 32],
            parameters: [7; 32],
            release: release.id(),
            cell_context: cell_discovery_context_digest(release.context()).unwrap(),
            signer_key_id: key_id,
            generation: 1,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        &key,
    )
    .unwrap();
    (key, pin, release, auth)
}
fn expectation(pin: &CellPqKeyPinV2) -> CellPqReleaseExpectationV2<'_> {
    CellPqReleaseExpectationV2 {
        network: [6; 32],
        parameters: [7; 32],
        key: pin,
        sequence: 4,
        now: 300,
    }
}
#[test]
fn signed_release_binds_every_byte_without_chunk_signatures() {
    let (_, pin, release, auth) = fixture();
    let raw = auth.encode().unwrap();
    assert_eq!(raw.len(), 3509);
    let expected = expectation(&pin);
    let proof = auth.verify_at(&release, &expected).unwrap();
    assert_eq!(proof.release_at(300).unwrap().id(), release.id());
    assert!(proof.release_at(299).is_err());
    assert!(proof.release_at(900).is_err());
    for index in 0..200 {
        let mut forged = raw.clone();
        forged[index] ^= 1;
        assert!(
            CellPqReleaseAuthorizationV2::decode(&forged)
                .and_then(|a| a.verify_at(&release, &expected))
                .is_err(),
            "accepted byte {index}"
        );
    }
    for index in [200, 1000, 3508] {
        let mut forged = raw.clone();
        forged[index] ^= 1;
        assert!(CellPqReleaseAuthorizationV2::decode(&forged)
            .unwrap()
            .verify_at(&release, &expected)
            .is_err());
    }
    for size in [0, 199, 200, 335, 3508, 3510] {
        let mut wire = raw.clone();
        wire.resize(size, 0);
        assert!(CellPqReleaseAuthorizationV2::decode(&wire).is_err());
    }
}
#[test]
fn release_current_authority_time_and_withdrawal_are_independent_gates() {
    let (key, pin, release, auth) = fixture();
    let mut other = pin.clone();
    other.generation = 2;
    assert!(auth.verify_at(&release, &expectation(&other)).is_err());
    other = pin.clone();
    other.revoked_at = Some(300);
    assert!(auth.verify_at(&release, &expectation(&other)).is_err());
    other = pin.clone();
    other.expires_at = 300;
    assert!(auth.verify_at(&release, &expectation(&other)).is_err());
    other = pin.clone();
    other.not_before = 301;
    assert!(auth.verify_at(&release, &expectation(&other)).is_err());
    let mut e = expectation(&pin);
    e.sequence = 3;
    assert!(auth.verify_at(&release, &e).is_err());
    e = expectation(&pin);
    e.now = 199;
    assert!(auth.verify_at(&release, &e).is_err());
    e = expectation(&pin);
    e.now = 900;
    assert!(auth.verify_at(&release, &e).is_err());
    let mut withdrawn = auth.statement.clone();
    withdrawn.withdrawn = true;
    let withdrawn = CellPqReleaseAuthorizationV2::sign(withdrawn, &key).unwrap();
    assert!(withdrawn.verify_at(&release, &expectation(&pin)).is_err());
    other = pin.clone();
    other.revoked_at = Some(450);
    assert_eq!(
        auth.verify_at(&release, &expectation(&other))
            .unwrap()
            .expires_at(),
        450
    );
    let wrong = CellReleaseManifestV1::new(release.context().clone(), vec![[10; 32]]).unwrap();
    assert!(auth.verify_at(&wrong, &expectation(&pin)).is_err());
}
#[test]
fn authority_roster_is_strict_bounded_and_commits_revocation() {
    let (key, pin, _, _) = fixture();
    assert!(CellPqKeyPinsV2::new(vec![]).is_err());
    assert!(CellPqKeyPinsV2::new(vec![pin.clone(); 65]).is_err());
    assert!(CellPqKeyPinsV2::new(vec![pin.clone(), pin.clone()]).is_err());
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let sig = key.sign_exact_message(b"test").unwrap();
    assert_eq!(
        keys.verify(pin.key_id, 1, 300, b"test", &sig).unwrap(),
        1000
    );
    assert!(keys.verify(pin.key_id, 2, 300, b"test", &sig).is_err());
    assert!(keys.verify([1; 32], 1, 300, b"test", &sig).is_err());
    assert!(keys.verify(pin.key_id, 1, 1000, b"test", &sig).is_err());
    let mut changed = pin.clone();
    changed.revoked_at = Some(500);
    let changed_keys = CellPqKeyPinsV2::new(vec![changed]).unwrap();
    assert_ne!(keys.digest(), changed_keys.digest());
    assert!(changed_keys
        .verify(pin.key_id, 1, 500, b"test", &sig)
        .is_err());
    let mut bad = pin;
    bad.spki[17] ^= 1;
    assert!(CellPqKeyPinsV2::new(vec![bad]).is_err());
}
