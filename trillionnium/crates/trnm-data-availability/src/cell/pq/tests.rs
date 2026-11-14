use super::*;
use zeroize::Zeroizing;

#[test]
fn retained_release_key_matches_fresh_verification_for_successive_valid_authorizations() {
    let (key, pin, release, original) = fixture();
    let pins = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let roster_digest = pins.digest();
    for sequence in [4, 5] {
        let mut statement = original.statement().clone();
        statement.sequence = sequence;
        let signed = CellPqReleaseAuthorizationV2::sign(statement, &key).unwrap();
        let mut current = expectation(&pin);
        current.sequence = sequence;
        current.now += sequence;
        let fresh = signed.verify_at(&release, &current).unwrap();
        let retained = signed
            .verify_at_with_pins(&release, &current, &pins)
            .unwrap();
        assert_eq!(
            fresh.release_at(&current).unwrap(),
            retained.release_at(&current).unwrap()
        );
        assert_eq!(fresh.expires_at(), retained.expires_at());
    }
    assert_eq!(pins.digest(), roster_digest);
}

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
    assert_eq!(proof.release_at(&expected).unwrap().id(), release.id());
    let mut current = expectation(&pin);
    current.now = 299;
    assert!(proof.release_at(&current).is_err());
    current.now = 900;
    assert!(proof.release_at(&current).is_err());
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

#[test]
fn cached_release_rechecks_current_retirement_rotation_scope_and_sequence() {
    let (_, pin, release, auth) = fixture();
    let checked = auth.verify_at(&release, &expectation(&pin)).unwrap();
    let mut changed = pin.clone();
    changed.revoked_at = Some(301);
    let mut current = expectation(&changed);
    current.now = 301;
    assert!(checked.release_at(&current).is_err());
    changed = pin.clone();
    changed.generation += 1;
    assert!(checked.release_at(&expectation(&changed)).is_err());
    changed = pin.clone();
    changed.not_before = 301;
    assert!(checked.release_at(&expectation(&changed)).is_err());
    changed = pin.clone();
    changed.expires_at = 300;
    assert!(checked.release_at(&expectation(&changed)).is_err());
    changed = pin.clone();
    changed.spki[17] ^= 1;
    assert!(checked.release_at(&expectation(&changed)).is_err());
    let mut current = expectation(&pin);
    current.sequence += 1;
    assert!(checked.release_at(&current).is_err());
    current = expectation(&pin);
    current.network[0] ^= 1;
    assert!(checked.release_at(&current).is_err());
    current = expectation(&pin);
    current.parameters[0] ^= 1;
    assert!(checked.release_at(&current).is_err());
    assert_eq!(
        checked.release_at(&expectation(&pin)).unwrap().id(),
        release.id()
    );
}

#[test]
fn selecting_old_content_requires_a_new_owner_approved_sequence() {
    let (key, pin, release, auth) = fixture();
    let old = auth.verify_at(&release, &expectation(&pin)).unwrap();
    let mut current = expectation(&pin);
    current.sequence = 5;
    assert!(old.release_at(&current).is_err());
    assert!(auth.verify_at(&release, &current).is_err());
    // Re-selecting identical content is allowed only with a fresh signed
    // sequence supplied by the external owner, never by lowering its floor.
    let mut selected = auth.statement().clone();
    selected.sequence = 5;
    let renewed = CellPqReleaseAuthorizationV2::sign(selected, &key).unwrap();
    let checked = renewed.verify_at(&release, &current).unwrap();
    assert_eq!(checked.release_at(&current).unwrap().id(), release.id());
    assert!(checked.release_at(&expectation(&pin)).is_err());
}

#[test]
fn retained_verifier_matches_the_complete_pin_and_clones_share_only_public_expansion() {
    let (_, pin, _, _) = fixture();
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let cloned = keys.clone();
    assert!(std::ptr::eq(
        keys.verifier_for(&pin).unwrap(),
        cloned.verifier_for(&pin).unwrap()
    ));
    for field in 0..7 {
        let mut changed = pin.clone();
        match field {
            0 => changed.key_id[0] ^= 1,
            1 => changed.spki[30] ^= 1,
            2 => changed.generation += 1,
            3 => changed.not_before += 1,
            4 => changed.expires_at -= 1,
            5 => changed.revoked_at = Some(900),
            6 => changed.revoked_at = Some(0),
            _ => unreachable!(),
        }
        assert!(keys.verifier_for(&changed).is_err(), "field {field}");
    }
}

#[test]
fn retained_release_verifier_rechecks_signature_authority_and_still_live_pin_changes() {
    let (_, pin, release, auth) = fixture();
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let expected = expectation(&pin);
    let proof = auth
        .verify_at_with_pins(&release, &expected, &keys)
        .unwrap();
    assert_eq!(proof.release_at(&expected).unwrap(), &release);
    let mut bad_signature = auth.clone();
    bad_signature.signature[0] ^= 1;
    assert!(bad_signature
        .verify_at_with_pins(&release, &expected, &keys)
        .is_err());
    let mut changed_message = auth.clone();
    changed_message.statement.sequence += 1;
    let mut next = expectation(&pin);
    next.sequence += 1;
    assert!(changed_message
        .verify_at_with_pins(&release, &next, &keys)
        .is_err());
    for field in 0..3 {
        let mut changed = pin.clone();
        match field {
            0 => changed.not_before += 1,
            1 => changed.expires_at -= 1,
            2 => changed.revoked_at = Some(900),
            _ => unreachable!(),
        }
        // This current pin is valid on its own but cannot borrow a retained
        // verifier from a roster carrying different authority metadata.
        assert!(auth.verify_at(&release, &expectation(&changed)).is_ok());
        assert!(auth
            .verify_at_with_pins(&release, &expectation(&changed), &keys)
            .is_err());
    }
    next = expectation(&pin);
    next.sequence += 1;
    assert!(proof.release_at(&next).is_err());
    next = expectation(&pin);
    next.now = 900;
    assert!(proof.release_at(&next).is_err());
    assert!(auth.verify_at_with_pins(&release, &expected, &keys).is_ok());
}
