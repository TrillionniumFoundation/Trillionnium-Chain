use super::*;

#[test]
fn retained_verifiers_recheck_each_actual_message_and_signature() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<PqReleaseAuthorityV1>();
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let first = metadata(&a, role, 20);
    let first_signatures = sign_metadata(&f, &first);
    a.accept(&first, &first_signatures, 20).unwrap();

    let next = metadata(&a, role, 21);
    let before = a.checkpoint();
    assert_eq!(
        a.accept(&next, &first_signatures, 21),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    let valid = sign_metadata(&f, &next);
    let mut corrupted = valid.clone();
    corrupted[0].signature[22] ^= 1;
    assert_eq!(
        a.accept(&next, &corrupted, 21),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.role_version(role), 1);
    assert_eq!(a.current_content(role), Some(first.content));
    assert_eq!(a.accept(&next, &valid, 21).unwrap().version(), 2);
    assert_eq!(
        a.check_current(role, next.content, a.checkpoint(), next.expires_at),
        Err(PqReleaseErrorV1::Expired)
    );
}

#[test]
fn retained_verifiers_require_current_role_membership_and_exact_spki() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let m = metadata(&a, role, 20);
    let before = a.checkpoint();
    let offline = signatures(&f, &f.root.offline_root, &m.signing_message());
    assert_eq!(
        a.accept(&m, &offline, 20),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    let valid = sign_metadata(&f, &m);
    let id = valid[0].key_id;

    // White-box faults check the private retained-key invariant. No production
    // API exposes the root or this map for mutation after complete validation.
    let saved = Arc::get_mut(&mut a.verifiers).unwrap().remove(&id).unwrap();
    assert_eq!(a.accept(&m, &valid, 20), Err(PqReleaseErrorV1::InvalidKey));
    let (other_id, other_spki) = f.root.offline_root.keys.first_key_value().unwrap();
    Arc::get_mut(&mut a.verifiers).unwrap().insert(
        id,
        PqNativeVerifier::from_pinned_spki(other_spki, *other_id).unwrap(),
    );
    assert_eq!(a.accept(&m, &valid, 20), Err(PqReleaseErrorV1::InvalidKey));
    Arc::get_mut(&mut a.verifiers).unwrap().insert(id, saved);
    a.root
        .roles
        .get_mut(&role)
        .unwrap()
        .keys
        .get_mut(&id)
        .unwrap()[30] ^= 1;
    assert_eq!(a.accept(&m, &valid, 20), Err(PqReleaseErrorV1::InvalidKey));
    a.root
        .roles
        .get_mut(&role)
        .unwrap()
        .keys
        .get_mut(&id)
        .unwrap()[30] ^= 1;
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.role_version(role), 0);
    a.accept(&m, &valid, 20).unwrap();
}

#[test]
fn retained_verifiers_rotation_replaces_keys_only_after_both_quorums() {
    let f = fixture(0);
    let mut a = authority(&f);
    let old_root = a.root.clone();
    let old_digest = a.root_digest();
    let before = a.checkpoint();
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = old_digest;
    let message = next.signing_message().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&successor, &next.offline_root, &message);
    let mut corrupted = new.clone();
    corrupted[0].signature[22] ^= 1;
    assert_eq!(
        a.rotate_root(next.clone(), &old, &corrupted, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(a.root, old_root);
    assert_eq!(a.root_digest(), old_digest);
    assert_eq!(a.checkpoint(), before);
    assert_eq!(
        a.verifiers.keys().copied().collect::<BTreeSet<_>>(),
        old_root.all_keys()
    );
    assert!(a.retired.is_empty());

    // The old authority remains usable after the failed successor quorum.
    let role = PqReleaseRoleV1::NodeSoftware;
    let m = metadata(&a, role, 30);
    a.accept(&m, &sign_metadata(&f, &m), 21).unwrap();
    let next_keys = next.all_keys();
    a.rotate_root(next, &old, &new, 22).unwrap();
    assert_eq!(a.root_generation(), 2);
    assert_eq!(
        a.verifiers.keys().copied().collect::<BTreeSet<_>>(),
        next_keys
    );
    assert_eq!(a.retired, old_root.all_keys());
    let m = metadata(&a, role, 31);
    let before = a.checkpoint();
    assert_eq!(
        a.accept(&m, &sign_metadata(&f, &m), 23),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    assert_eq!(a.checkpoint(), before);
    a.accept(&m, &sign_metadata(&successor, &m), 23).unwrap();
}

#[test]
fn retained_verifiers_recovery_rechecks_signatures_and_current_generation() {
    let f = fixture(0);
    let mut a = authority(&f);
    let node = metadata(&a, PqReleaseRoleV1::NodeSoftware, 20);
    let node_signatures = sign_metadata(&f, &node);
    a.accept(&node, &node_signatures, 20).unwrap();
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&successor, &next.offline_root, &message);
    a.rotate_root(next.clone(), &old, &new, 21).unwrap();
    let protocol = metadata(&a, PqReleaseRoleV1::ProtocolConfiguration, 21);
    let protocol_signatures = sign_metadata(&successor, &protocol);
    a.accept(&protocol, &protocol_signatures, 22).unwrap();
    let events = vec![
        PqReleaseEventV1::Release {
            metadata: node.clone(),
            signatures: node_signatures,
            observed_at: 20,
        },
        PqReleaseEventV1::RootRotation {
            root: next.clone(),
            old_signatures: old,
            new_signatures: new,
            observed_at: 21,
        },
        PqReleaseEventV1::Release {
            metadata: protocol.clone(),
            signatures: protocol_signatures,
            observed_at: 22,
        },
    ];
    let initial_pin = f.root.digest().unwrap();
    let expected = a.checkpoint();
    let recover = |events: &[PqReleaseEventV1], checkpoint| {
        PqReleaseAuthorityV1::recover_pinned(f.root.clone(), initial_pin, 10, events, checkpoint)
    };
    let mut recovered = recover(&events, expected).unwrap();
    assert_eq!(recovered.root_generation(), 2);
    assert_eq!(recovered.root_digest(), a.root_digest());
    assert_eq!(recovered.role_version(node.role), 1);
    assert_eq!(recovered.role_version(protocol.role), 1);
    assert_eq!(recovered.retired, f.root.all_keys());
    assert_eq!(
        recovered.verifiers.keys().copied().collect::<BTreeSet<_>>(),
        next.all_keys()
    );
    assert_eq!(
        recovered.check_current(node.role, node.content, expected, 22),
        Err(PqReleaseErrorV1::WrongAuthority)
    );
    recovered
        .check_current(protocol.role, protocol.content, expected, 22)
        .unwrap();

    // Every original and successor signature is checked in each reconstruction.
    for corrupted_quorum in 0..4 {
        let mut altered = events.clone();
        let signatures = match corrupted_quorum {
            0 => match &mut altered[0] {
                PqReleaseEventV1::Release { signatures, .. } => signatures,
                _ => unreachable!(),
            },
            1 | 2 => match &mut altered[1] {
                PqReleaseEventV1::RootRotation {
                    old_signatures,
                    new_signatures,
                    ..
                } => {
                    if corrupted_quorum == 1 {
                        old_signatures
                    } else {
                        new_signatures
                    }
                }
                _ => unreachable!(),
            },
            3 => match &mut altered[2] {
                PqReleaseEventV1::Release { signatures, .. } => signatures,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        signatures[0].signature[22] ^= 1;
        assert_eq!(
            recover(&altered, expected).err(),
            Some(PqReleaseErrorV1::SignatureRejected)
        );
    }
    assert_eq!(
        recover(&events, [99; 32]).err(),
        Some(PqReleaseErrorV1::CheckpointConflict)
    );
    let current = metadata(&recovered, node.role, 22);
    assert_eq!(
        recovered.accept(&current, &sign_metadata(&f, &current), 23),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    recovered
        .accept(&current, &sign_metadata(&successor, &current), 23)
        .unwrap();
}
