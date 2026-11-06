use super::*;

#[test]
fn validated_root_keeps_public_encoding_and_owner_time_distinct() {
    let f = fixture(0);
    let public_message = f.root.signing_message().unwrap();
    let public_digest = f.root.digest().unwrap();
    for now in [0, 10, f.root.expires_at - 1] {
        let a = PqReleaseAuthorityV1::bootstrap_pinned(f.root.clone(), public_digest, now).unwrap();
        assert_eq!(a.root_digest(), public_digest);
        assert_eq!(
            a.checkpoint(),
            next_checkpoint([0; 32], &public_message, now)
        );
    }
    // Public signing bytes are timeless; an owner still rejects an expired root.
    assert_eq!(
        PqReleaseAuthorityV1::bootstrap_pinned(f.root.clone(), public_digest, f.root.expires_at)
            .err(),
        Some(PqReleaseErrorV1::InvalidRoot)
    );
    assert_eq!(f.root.signing_message().unwrap(), public_message);
    assert_eq!(f.root.digest().unwrap(), public_digest);
}

#[test]
fn validated_root_still_checks_all_keys_roles_and_original_error_precedence() {
    let f = fixture(0);
    let original_pin = f.root.digest().unwrap();
    for role in std::iter::once(None).chain(ROLES.into_iter().map(Some)) {
        let keys = match role {
            None => &f.root.offline_root,
            Some(role) => &f.root.roles[&role],
        };
        for key_id in keys.keys.keys() {
            let mut bad = f.root.clone();
            let keys = match role {
                None => &mut bad.offline_root,
                Some(role) => bad.roles.get_mut(&role).unwrap(),
            };
            keys.keys.get_mut(key_id).unwrap()[0] ^= 1;
            assert_eq!(bad.signing_message(), Err(PqReleaseErrorV1::InvalidKey));
            assert_eq!(bad.digest(), Err(PqReleaseErrorV1::InvalidKey));
            assert_eq!(
                PqReleaseAuthorityV1::bootstrap_pinned(bad, original_pin, 10).err(),
                Some(PqReleaseErrorV1::InvalidKey)
            );
        }
    }
    let mut bad = f.root.clone();
    bad.expires_at = 10;
    bad.offline_root.threshold = 0;
    assert_eq!(
        PqReleaseAuthorityV1::bootstrap_pinned(bad.clone(), [0; 32], 10).err(),
        Some(PqReleaseErrorV1::InvalidRoot)
    );
    assert_eq!(bad.digest(), Err(PqReleaseErrorV1::InvalidThreshold));
    bad = f.root.clone();
    bad.roles.remove(&PqReleaseRoleV1::CellActivation);
    assert_eq!(bad.digest(), Err(PqReleaseErrorV1::MissingRole));
    bad = f.root.clone();
    bad.roles
        .insert(PqReleaseRoleV1::CellActivation, bad.offline_root.clone());
    assert_eq!(bad.digest(), Err(PqReleaseErrorV1::CrossRoleKey));
}

#[test]
fn validated_root_rotation_retains_both_quorums_and_exact_checkpoint_message() {
    let f = fixture(0);
    let next_fixture = fixture(20);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let mut next = next_fixture.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let digest = next.digest().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&next_fixture, &next.offline_root, &message);
    let mut corrupted = old.clone();
    corrupted[0].signature[22] ^= 1;
    assert_eq!(
        a.rotate_root(next.clone(), &corrupted, &new, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(
        a.rotate_root(next.clone(), &old, &new[..1], 20),
        Err(PqReleaseErrorV1::InsufficientSignatures)
    );
    let mut altered = next.clone();
    altered.expires_at -= 1;
    assert_eq!(
        a.rotate_root(altered, &old, &new, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(a.checkpoint(), before);
    let expected = next_checkpoint(before, &message, 20);
    assert_eq!(a.rotate_root(next, &old, &new, 20), Ok(expected));
    assert_eq!(a.checkpoint(), expected);
    assert_eq!(a.root_digest(), digest);
}

#[test]
fn validated_root_rotation_keeps_clock_key_and_sequence_rejection_order() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let mut next = f.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    next.network_id = [99; 32];
    *next.offline_root.keys.values_mut().next().unwrap() = vec![0; 1974];
    assert_eq!(
        a.rotate_root(next.clone(), &[], &[], 9),
        Err(PqReleaseErrorV1::ClockRollback)
    );
    assert_eq!(
        a.rotate_root(next.clone(), &[], &[], 20),
        Err(PqReleaseErrorV1::InvalidKey)
    );
    next.offline_root = f.root.offline_root.clone();
    assert_eq!(
        a.rotate_root(next, &[], &[], 20),
        Err(PqReleaseErrorV1::RootSequence)
    );
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.root_generation(), 1);
}
