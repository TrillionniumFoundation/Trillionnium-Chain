use super::*;

#[test]
fn current_bundle_check_requires_exact_role_content_and_independent_checkpoint() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let mut b = bundle(a.bundle_signer_identity(role));
    let mut m = metadata(&a, role, 20);
    m.content = b.bundle_digest.0;
    let signed = sign_metadata(&f, &m);
    b.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signed).unwrap());
    let (verified, observation) = a.accept_bundle(&b, &[], &m, &signed, 20).unwrap();
    let retained_checkpoint = a.checkpoint();
    let before = (a.role_version(role), a.time_floor, a.event_count);
    assert_eq!(
        a.check_current(role, verified.bundle_digest.0, retained_checkpoint, 20),
        Ok(())
    );
    assert_eq!(
        a.check_current(role, observation.content(), [9; 32], 20),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
    assert_eq!(
        a.check_current(role, [8; 32], retained_checkpoint, 20),
        Err(PqReleaseErrorV1::NotCurrent)
    );
    assert_eq!(
        a.check_current(
            PqReleaseRoleV1::ProtocolConfiguration,
            observation.content(),
            retained_checkpoint,
            20,
        ),
        Err(PqReleaseErrorV1::NotCurrent)
    );
    assert_eq!(a.checkpoint(), retained_checkpoint);
    assert_eq!((a.role_version(role), a.time_floor, a.event_count), before);
}

#[test]
fn current_check_uses_live_expiry_and_committed_clock_floor_without_mutating_it() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::ProtocolConfiguration;
    let mut m = metadata(&a, role, 20);
    m.expires_at = 30;
    a.accept(&m, &sign_metadata(&f, &m), 20).unwrap();
    let checkpoint = a.checkpoint();
    assert_eq!(a.check_current(role, m.content, checkpoint, 29), Ok(()));
    assert_eq!(
        a.check_current(role, m.content, checkpoint, 19),
        Err(PqReleaseErrorV1::ClockRollback)
    );
    assert_eq!(
        a.check_current(role, m.content, checkpoint, 30),
        Err(PqReleaseErrorV1::Expired)
    );
    assert_eq!(
        a.check_current(role, m.content, checkpoint, f.root.expires_at),
        Err(PqReleaseErrorV1::Expired)
    );
    // This read-only component does not persist that a clock observed 29 or 30.
    // The external trusted clock must itself prevent later observation rollback.
    assert_eq!(a.check_current(role, m.content, checkpoint, 20), Ok(()));
    assert_eq!(a.time_floor, 20);
    assert_eq!(a.event_count, 1);
    assert_eq!(a.checkpoint(), checkpoint);
}

#[test]
fn current_check_after_rotation_and_recovery_requires_current_publisher_quorum() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let m = metadata(&a, role, 20);
    let signed = sign_metadata(&f, &m);
    a.accept(&m, &signed, 20).unwrap();
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let old_signatures = signatures(&f, &f.root.offline_root, &message);
    let new_signatures = signatures(&successor, &next.offline_root, &message);
    a.rotate_root(next.clone(), &old_signatures, &new_signatures, 21)
        .unwrap();
    let frontier = a.checkpoint();
    assert_eq!(a.current_content(role), Some(m.content));
    assert_eq!(
        a.check_current(role, m.content, frontier, 22),
        Err(PqReleaseErrorV1::WrongAuthority)
    );
    let events = [
        PqReleaseEventV1::Release {
            metadata: m.clone(),
            signatures: signed,
            observed_at: 20,
        },
        PqReleaseEventV1::RootRotation {
            root: next,
            old_signatures,
            new_signatures,
            observed_at: 21,
        },
    ];
    let mut recovered = PqReleaseAuthorityV1::recover_pinned(
        f.root.clone(),
        f.root.digest().unwrap(),
        10,
        &events,
        frontier,
    )
    .unwrap();
    assert_eq!(
        recovered.check_current(role, m.content, frontier, 22),
        Err(PqReleaseErrorV1::WrongAuthority)
    );
    let renewed = metadata(&recovered, role, 20);
    assert_eq!(
        recovered.accept(&renewed, &sign_metadata(&f, &renewed), 22),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    recovered
        .accept(&renewed, &sign_metadata(&successor, &renewed), 22)
        .unwrap();
    assert_eq!(
        recovered.check_current(role, m.content, recovered.checkpoint(), 22),
        Ok(())
    );
    assert_eq!(
        recovered.check_current(role, m.content, frontier, 22),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
}

#[test]
fn current_check_rejects_replaced_content_and_rolled_back_owner_against_future_frontier() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let first = metadata(&a, role, 20);
    let first_signed = sign_metadata(&f, &first);
    let observation = a.accept(&first, &first_signed, 20).unwrap();
    let old_checkpoint = a.checkpoint();
    let first_event = PqReleaseEventV1::Release {
        metadata: first.clone(),
        signatures: first_signed,
        observed_at: 20,
    };
    let second = metadata(&a, role, 21);
    let second_signed = sign_metadata(&f, &second);
    a.accept(&second, &second_signed, 21).unwrap();
    let future_frontier = a.checkpoint();
    assert_eq!(
        a.check_current(role, observation.content(), future_frontier, 21),
        Err(PqReleaseErrorV1::NotCurrent)
    );
    assert_eq!(
        a.check_current(role, second.content, future_frontier, 21),
        Ok(())
    );
    assert!(matches!(
        PqReleaseAuthorityV1::recover_pinned(
            f.root.clone(),
            f.root.digest().unwrap(),
            10,
            std::slice::from_ref(&first_event),
            future_frontier,
        ),
        Err(PqReleaseErrorV1::CheckpointConflict)
    ));
    // An old but internally consistent owner cannot pass the independently
    // retained future checkpoint at a later use boundary either.
    let old = PqReleaseAuthorityV1::recover_pinned(
        f.root.clone(),
        f.root.digest().unwrap(),
        10,
        &[first_event],
        old_checkpoint,
    )
    .unwrap();
    assert_eq!(
        old.check_current(role, first.content, future_frontier, 21),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
    assert_eq!(old.checkpoint(), old_checkpoint);
}

#[test]
fn current_activation_rechecks_publication_expiry_and_replacement() {
    let f = fixture(0);
    let mut a = authority(&f);
    let mut manifest = metadata(&a, PqReleaseRoleV1::CellManifest, 40);
    manifest.expires_at = 30;
    a.accept(&manifest, &sign_metadata(&f, &manifest), 20)
        .unwrap();
    let activation = metadata(&a, PqReleaseRoleV1::CellActivation, 40);
    a.accept(&activation, &sign_metadata(&f, &activation), 21)
        .unwrap();
    assert_eq!(
        a.check_current(activation.role, activation.content, a.checkpoint(), 29),
        Ok(())
    );
    assert_eq!(
        a.check_current(activation.role, activation.content, a.checkpoint(), 30),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    let replacement = metadata(&a, PqReleaseRoleV1::CellManifest, 41);
    a.accept(&replacement, &sign_metadata(&f, &replacement), 30)
        .unwrap();
    assert_eq!(
        a.check_current(activation.role, activation.content, a.checkpoint(), 30),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    let renewed = metadata(&a, PqReleaseRoleV1::CellManifest, 40);
    let renewed = PqReleaseMetadataV1 {
        approved_content_rollback: true,
        ..renewed
    };
    a.accept(&renewed, &sign_metadata(&f, &renewed), 31)
        .unwrap();
    assert_eq!(
        a.check_current(activation.role, activation.content, a.checkpoint(), 31),
        Ok(())
    );
}
