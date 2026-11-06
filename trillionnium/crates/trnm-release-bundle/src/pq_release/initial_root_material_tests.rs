use super::*;

fn prepared(f: &Fixture) -> PqInitialRootKeyMaterialV1 {
    PqInitialRootKeyMaterialV1::prepare_pinned(f.root.clone(), f.root.digest().unwrap(), 10)
        .unwrap()
}

fn from_material(
    f: &Fixture,
    material: &PqInitialRootKeyMaterialV1,
    at: u64,
) -> PqReleaseAuthorityV1 {
    PqReleaseAuthorityV1::bootstrap_pinned_with_material(
        f.root.clone(),
        f.root.digest().unwrap(),
        at,
        material,
    )
    .unwrap()
}

#[test]
fn initial_root_material_binds_every_root_field_and_independent_pin() {
    let f = fixture(0);
    let pin = f.root.digest().unwrap();
    let material = prepared(&f);
    let mut changes = Vec::new();
    let mut changed = f.root.clone();
    changed.network_id = [13; 32];
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.generation = 2;
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.previous_root_digest = [9; 32];
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.expires_at -= 1;
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.offline_root.threshold = 1;
    changes.push(changed);
    let mut changed = f.root.clone();
    changed
        .roles
        .get_mut(&PqReleaseRoleV1::NodeSoftware)
        .unwrap()
        .threshold = 1;
    changes.push(changed);
    let mut changed = f.root.clone();
    let node = changed.roles[&PqReleaseRoleV1::NodeSoftware].clone();
    let protocol = changed.roles[&PqReleaseRoleV1::ProtocolConfiguration].clone();
    changed
        .roles
        .insert(PqReleaseRoleV1::NodeSoftware, protocol);
    changed
        .roles
        .insert(PqReleaseRoleV1::ProtocolConfiguration, node);
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.offline_root.keys.values_mut().next().unwrap()[30] ^= 1;
    changes.push(changed);
    let mut changed = f.root.clone();
    changed.roles.remove(&PqReleaseRoleV1::CellActivation);
    changes.push(changed);
    for changed in changes {
        assert!(!material.matches_root(&changed, pin));
        let original = PqReleaseAuthorityV1::bootstrap_pinned(changed.clone(), pin, 10).err();
        assert!(original.is_some());
        assert_eq!(
            PqReleaseAuthorityV1::bootstrap_pinned_with_material(changed, pin, 10, &material).err(),
            original
        );
    }
    assert_eq!(
        PqReleaseAuthorityV1::bootstrap_pinned_with_material(
            f.root.clone(),
            [9; 32],
            10,
            &material
        )
        .err(),
        Some(PqReleaseErrorV1::RootPin)
    );
    let mut otherwise_valid = f.root.clone();
    otherwise_valid.expires_at -= 1;
    let other_pin = otherwise_valid.digest().unwrap();
    assert!(PqReleaseAuthorityV1::bootstrap_pinned(otherwise_valid.clone(), other_pin, 10).is_ok());
    assert_eq!(
        PqReleaseAuthorityV1::bootstrap_pinned_with_material(
            otherwise_valid,
            other_pin,
            10,
            &material
        )
        .err(),
        Some(PqReleaseErrorV1::RootPin)
    );
    assert!(material.matches_root(&f.root, pin));
    let mut a = from_material(&f, &material, 10);
    accept(&f, &mut a, PqReleaseRoleV1::NodeSoftware, 20);
}

#[test]
fn initial_root_material_creates_independent_empty_state_and_fresh_time() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<PqInitialRootKeyMaterialV1>();
    require_send_sync::<PqReleaseAuthorityV1>();
    let f = fixture(0);
    let material = prepared(&f);
    let mut first = from_material(&f, &material, 10);
    let second = from_material(&f, &material, 10);
    assert!(Arc::ptr_eq(&first.verifiers, &second.verifiers));
    let initial = second.checkpoint();
    accept(&f, &mut first, PqReleaseRoleV1::NodeSoftware, 20);
    assert_ne!(first.checkpoint(), initial);
    assert_eq!(second.checkpoint(), initial);
    assert!(second.versions.is_empty());
    assert!(second.current.is_empty());
    assert!(second.history.is_empty());
    assert!(second.retired.is_empty());
    assert_eq!(second.event_count, 0);
    assert_eq!(second.time_floor, 10);
    let third = from_material(&f, &material, 21);
    assert_ne!(third.checkpoint(), initial);
    assert_eq!(third.time_floor, 21);
    assert_eq!(third.event_count, 0);
    assert!(third.versions.is_empty());
    assert!(third.current.is_empty());
    assert!(third.history.is_empty());
    assert!(third.retired.is_empty());
    let expected =
        PqReleaseAuthorityV1::bootstrap_pinned(f.root.clone(), f.root.digest().unwrap(), 21)
            .unwrap();
    assert_eq!(third.checkpoint(), expected.checkpoint());
    assert_eq!(
        PqReleaseAuthorityV1::bootstrap_pinned_with_material(
            f.root.clone(),
            f.root.digest().unwrap(),
            f.root.expires_at,
            &material
        )
        .err(),
        Some(PqReleaseErrorV1::InvalidRoot)
    );
}

#[test]
fn initial_root_material_never_reuses_a_quorum_or_signature_result() {
    let f = fixture(0);
    let material = prepared(&f);
    let mut first = from_material(&f, &material, 10);
    let m = metadata(&first, PqReleaseRoleV1::NodeSoftware, 20);
    let valid = sign_metadata(&f, &m);
    first.accept(&m, &valid, 20).unwrap();
    let mut second = from_material(&f, &material, 10);
    let initial = second.checkpoint();
    assert_eq!(
        second.accept(&m, &valid[..1], 20),
        Err(PqReleaseErrorV1::InsufficientSignatures)
    );
    let duplicate = vec![valid[0].clone(), valid[0].clone()];
    assert_eq!(
        second.accept(&m, &duplicate, 20),
        Err(PqReleaseErrorV1::DuplicateSigner)
    );
    let cross_role = signatures(&f, &f.root.offline_root, &m.signing_message());
    assert_eq!(
        second.accept(&m, &cross_role, 20),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    let mut altered = m.clone();
    altered.content[0] ^= 1;
    assert_eq!(
        second.accept(&altered, &valid, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    let mut corrupt = valid.clone();
    corrupt[0].signature[22] ^= 1;
    assert_eq!(
        second.accept(&m, &corrupt, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(second.checkpoint(), initial);
    assert!(second.history.is_empty());
    second.accept(&m, &valid, 20).unwrap();
    assert_eq!(second.checkpoint(), first.checkpoint());
    assert_eq!(second.history, first.history);
    assert_eq!(
        second.check_current(m.role, m.content, second.checkpoint(), m.expires_at),
        Err(PqReleaseErrorV1::Expired)
    );
}

