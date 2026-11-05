use super::*;
use crate::{ArtifactEntryV0, BuildInputV0, BuilderProvenanceV0, ExactSourceV0, SbomPackageV0};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

struct Fixture {
    root: PqReleaseRootV1,
    keys: BTreeMap<ReleaseKeyIdV1, PqNativeSigningKey>,
}
fn fixture(offset: u8) -> Fixture {
    let mut keys = BTreeMap::new();
    let mut role_keys = |start: u8, count: u8, threshold| {
        let mut public = BTreeMap::new();
        for i in start..start + count {
            let seed = Zeroizing::new([offset + i; 32]);
            let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
            let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
            let key = PqNativeSigningKey::from_owned_seed(seed, id).unwrap();
            public.insert(id, spki.to_vec());
            keys.insert(id, key);
        }
        PqReleaseRoleKeysV1 {
            threshold,
            keys: public,
        }
    };
    let root_keys = role_keys(1, 2, 2);
    let roles = ROLES
        .into_iter()
        .enumerate()
        .map(|(i, role)| (role, role_keys(3 + i as u8 * 2, 2, 2)))
        .collect();
    Fixture {
        root: PqReleaseRootV1 {
            network_id: [12; 32],
            generation: 1,
            expires_at: 1000,
            previous_root_digest: [0; 32],
            offline_root: root_keys,
            roles,
        },
        keys,
    }
}
fn authority(f: &Fixture) -> PqReleaseAuthorityV1 {
    PqReleaseAuthorityV1::bootstrap_pinned(f.root.clone(), f.root.digest().unwrap(), 10).unwrap()
}
fn signatures(
    f: &Fixture,
    role: &PqReleaseRoleKeysV1,
    message: &[u8],
) -> Vec<PqReleaseSignatureV1> {
    role.keys
        .keys()
        .map(|id| PqReleaseSignatureV1 {
            key_id: *id,
            signature: f.keys[id].sign_exact_message(message).unwrap().to_vec(),
        })
        .collect()
}
fn metadata(a: &PqReleaseAuthorityV1, role: PqReleaseRoleV1, content: u8) -> PqReleaseMetadataV1 {
    PqReleaseMetadataV1 {
        network_id: [12; 32],
        role,
        root_generation: a.root_generation(),
        role_version: a.role_version(role) + 1,
        expires_at: 900,
        expected_checkpoint: a.checkpoint(),
        previous_content: a.current_content(role),
        content: [content; 32],
        approved_content_rollback: false,
    }
}
fn sign_metadata(f: &Fixture, m: &PqReleaseMetadataV1) -> Vec<PqReleaseSignatureV1> {
    signatures(f, &f.root.roles[&m.role], &m.signing_message())
}
fn accept(f: &Fixture, a: &mut PqReleaseAuthorityV1, role: PqReleaseRoleV1, content: u8) {
    let m = metadata(a, role, content);
    a.accept(&m, &sign_metadata(f, &m), 20).unwrap();
}

#[test]
fn actual_mldsa_quorum_advances_only_verified_role() {
    let f = fixture(0);
    let mut a = authority(&f);
    let m = metadata(&a, PqReleaseRoleV1::NodeSoftware, 20);
    let sig = sign_metadata(&f, &m);
    let receipt = a.accept(&m, &sig, 20).unwrap();
    assert_eq!(receipt.version(), 1);
    assert_eq!(receipt.content(), [20; 32]);
    assert_eq!(receipt.checkpoint(), a.checkpoint());
    assert_eq!(a.role_version(PqReleaseRoleV1::CellManifest), 0);
    assert_eq!(
        a.accept(&m, &sig, 21),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
}

#[test]
fn bootstrap_requires_out_of_band_pin_threshold_and_separate_keys() {
    let f = fixture(0);
    assert!(matches!(
        PqReleaseAuthorityV1::bootstrap_pinned(f.root.clone(), [9; 32], 10),
        Err(PqReleaseErrorV1::RootPin)
    ));
    let mut invalid = f.root.clone();
    invalid.offline_root.threshold = 0;
    assert_eq!(invalid.digest(), Err(PqReleaseErrorV1::InvalidThreshold));
    let mut invalid = f.root.clone();
    invalid
        .roles
        .insert(PqReleaseRoleV1::CellManifest, invalid.offline_root.clone());
    assert_eq!(invalid.digest(), Err(PqReleaseErrorV1::CrossRoleKey));
    let mut invalid = f.root.clone();
    invalid.roles.remove(&PqReleaseRoleV1::CellActivation);
    assert_eq!(invalid.digest(), Err(PqReleaseErrorV1::MissingRole));
    let mut invalid = f.root.clone();
    *invalid.offline_root.keys.values_mut().next().unwrap() = vec![0; 1974];
    assert_eq!(invalid.digest(), Err(PqReleaseErrorV1::InvalidKey));
}

#[test]
fn duplicates_corruption_and_cross_role_signatures_never_count_as_quorum() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let m = metadata(&a, PqReleaseRoleV1::NodeSoftware, 20);
    let sig = sign_metadata(&f, &m);
    assert_eq!(
        a.accept(&m, &sig[..1], 20),
        Err(PqReleaseErrorV1::InsufficientSignatures)
    );
    let dup = vec![sig[0].clone(), sig[0].clone()];
    assert_eq!(
        a.accept(&m, &dup, 20),
        Err(PqReleaseErrorV1::DuplicateSigner)
    );
    let wrong = signatures(
        &f,
        &f.root.roles[&PqReleaseRoleV1::CellManifest],
        &m.signing_message(),
    );
    assert_eq!(
        a.accept(&m, &wrong, 20),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    let mut corrupt = sig.clone();
    corrupt[0].signature[22] ^= 1;
    assert_eq!(
        a.accept(&m, &corrupt, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    corrupt[0].signature = vec![0; 64];
    assert_eq!(
        a.accept(&m, &corrupt, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.role_version(m.role), 0);
}

#[test]
fn signed_message_binds_role_network_expiry_content_and_full_checkpoint() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let original = metadata(&a, PqReleaseRoleV1::NodeSoftware, 20);
    let sig = sign_metadata(&f, &original);
    let mut m = original.clone();
    m.network_id = [8; 32];
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::WrongAuthority)
    );
    m = original.clone();
    m.root_generation += 1;
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::WrongAuthority)
    );
    m = original.clone();
    m.expected_checkpoint = [8; 32];
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
    m = original.clone();
    m.previous_content = Some([8; 32]);
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
    m = original.clone();
    m.role_version = 2;
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::VersionRollback)
    );
    m = original.clone();
    m.expires_at = 21;
    assert_eq!(a.accept(&m, &sig, 21), Err(PqReleaseErrorV1::Expired));
    m = original.clone();
    m.expires_at = 1001;
    assert_eq!(a.accept(&m, &sig, 20), Err(PqReleaseErrorV1::Expired));
    m = original.clone();
    m.content = [21; 32];
    assert_eq!(
        a.accept(&m, &sig, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    m = original.clone();
    m.role = PqReleaseRoleV1::ProtocolConfiguration;
    assert_eq!(a.accept(&m, &sig, 20), Err(PqReleaseErrorV1::UnknownSigner));
    assert_eq!(
        a.accept(&original, &sig, 9),
        Err(PqReleaseErrorV1::ClockRollback)
    );
    assert_eq!(a.checkpoint(), before);
}

#[test]
fn old_content_requires_new_signed_rollback_and_versions_never_decrease() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::CellManifest;
    accept(&f, &mut a, role, 40);
    accept(&f, &mut a, role, 41);
    let mut rollback = metadata(&a, role, 40);
    let unapproved = sign_metadata(&f, &rollback);
    assert_eq!(
        a.accept(&rollback, &unapproved, 20),
        Err(PqReleaseErrorV1::RollbackApproval)
    );
    rollback.approved_content_rollback = true;
    assert_eq!(
        a.accept(&rollback, &unapproved, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    let sig = sign_metadata(&f, &rollback);
    let receipt = a.accept(&rollback, &sig, 20).unwrap();
    assert_eq!(receipt.version(), 3);
    assert_eq!(receipt.content(), [40; 32]);
    let mut replay = metadata(&a, role, 41);
    replay.role_version = 1;
    replay.approved_content_rollback = true;
    assert_eq!(
        a.accept(&replay, &sign_metadata(&f, &replay), 20),
        Err(PqReleaseErrorV1::VersionRollback)
    );
}

#[test]
fn activation_has_distinct_quorum_and_requires_current_published_manifest() {
    let f = fixture(0);
    let mut a = authority(&f);
    let m = metadata(&a, PqReleaseRoleV1::CellActivation, 40);
    assert_eq!(
        a.accept(&m, &sign_metadata(&f, &m), 20),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    accept(&f, &mut a, PqReleaseRoleV1::CellManifest, 40);
    let m = metadata(&a, PqReleaseRoleV1::CellActivation, 40);
    let wrong = signatures(
        &f,
        &f.root.roles[&PqReleaseRoleV1::CellManifest],
        &m.signing_message(),
    );
    assert_eq!(
        a.accept(&m, &wrong, 20),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    a.accept(&m, &sign_metadata(&f, &m), 20).unwrap();
    accept(&f, &mut a, PqReleaseRoleV1::CellManifest, 41);
    accept(&f, &mut a, PqReleaseRoleV1::CellActivation, 41);
    for role in [
        PqReleaseRoleV1::CellManifest,
        PqReleaseRoleV1::CellActivation,
    ] {
        let mut rollback = metadata(&a, role, 40);
        rollback.approved_content_rollback = true;
        a.accept(&rollback, &sign_metadata(&f, &rollback), 20)
            .unwrap();
        assert_eq!(a.role_version(role), 3);
    }
}

#[test]
fn root_rotation_requires_old_and_new_quorums_not_candidate_self_authority() {
    let f = fixture(0);
    let mut a = authority(&f);
    let next_fixture = fixture(20);
    let mut next = next_fixture.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let old = signatures(&f, &f.root.offline_root, &message);
    let new = signatures(&next_fixture, &next.offline_root, &message);
    let candidate = signatures(&f, &f.root.roles[&PqReleaseRoleV1::CellManifest], &message);
    assert_eq!(
        a.rotate_root(next.clone(), &candidate, &new, 20),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    assert_eq!(
        a.rotate_root(next.clone(), &old, &new[..1], 20),
        Err(PqReleaseErrorV1::InsufficientSignatures)
    );
    let before = a.checkpoint();
    a.rotate_root(next.clone(), &old, &new, 20).unwrap();
    assert_ne!(a.checkpoint(), before);
    assert_eq!(a.root_generation(), 2);
    assert_eq!(
        a.rotate_root(next, &old, &new, 21),
        Err(PqReleaseErrorV1::RootSequence)
    );
    let m = metadata(&a, PqReleaseRoleV1::NodeSoftware, 22);
    assert_eq!(
        a.accept(&m, &sign_metadata(&f, &m), 21),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    a.accept(&m, &sign_metadata(&next_fixture, &m), 21).unwrap();
}

#[test]
fn retired_keys_cannot_be_reintroduced_even_with_valid_root_signatures() {
    let f = fixture(0);
    let mut a = authority(&f);
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    a.rotate_root(
        next.clone(),
        &signatures(&f, &f.root.offline_root, &message),
        &signatures(&successor, &next.offline_root, &message),
        20,
    )
    .unwrap();
    let mut resurrect = f.root.clone();
    resurrect.generation = 3;
    resurrect.previous_root_digest = a.root_digest();
    let message = resurrect.signing_message().unwrap();
    let checkpoint = a.checkpoint();
    assert_eq!(
        a.rotate_root(
            resurrect.clone(),
            &signatures(&successor, &next.offline_root, &message),
            &signatures(&f, &resurrect.offline_root, &message),
            21
        ),
        Err(PqReleaseErrorV1::RetiredKey)
    );
    assert_eq!(a.checkpoint(), checkpoint);
}

#[test]
fn root_rotation_preserves_content_versions_and_refuses_skipped_generation() {
    let f = fixture(0);
    let mut a = authority(&f);
    accept(&f, &mut a, PqReleaseRoleV1::NodeSoftware, 20);
    let mut next = f.root.clone();
    next.generation = 3;
    next.previous_root_digest = a.root_digest();
    let sig = signatures(&f, &f.root.offline_root, &next.signing_message().unwrap());
    assert_eq!(
        a.rotate_root(next.clone(), &sig, &sig, 20),
        Err(PqReleaseErrorV1::RootSequence)
    );
    next.generation = 2;
    let sig = signatures(&f, &f.root.offline_root, &next.signing_message().unwrap());
    a.rotate_root(next, &sig, &sig, 20).unwrap();
    assert_eq!(a.role_version(PqReleaseRoleV1::NodeSoftware), 1);
    let m = metadata(&a, PqReleaseRoleV1::NodeSoftware, 21);
    assert_eq!(
        a.accept(&m, &sign_metadata(&f, &m), 20).unwrap().version(),
        2
    );
}

fn bundle(identity: ReleaseDigestV1) -> ReleaseBundleV0 {
    let d = |x| Digest32V0([x; 32]);
    let exact = ExactSourceV0 {
        repository_digest: d(1),
        commit_digest: d(2),
        tree_digest: d(3),
        cargo_lock_digest: d(4),
        toolchain_digest: d(5),
        production_closure_digest: d(6),
        dirty: false,
    };
    let mut b = ReleaseBundleV0 {
        bundle_name: b"node".to_vec(),
        release_version: b"1".to_vec(),
        protocol_digest: d(7),
        exact_source: exact,
        artifacts: vec![ArtifactEntryV0 {
            logical_name: b"node".to_vec(),
            media_type: b"application/octet-stream".to_vec(),
            size_bytes: 11,
            content_digest: d(8),
            executable: true,
            platform_digest: d(9),
            source_path_digest: d(10),
        }],
        sbom_packages: vec![SbomPackageV0 {
            package_name: b"node".to_vec(),
            package_version: b"1".to_vec(),
            source_digest: d(2),
            package_checksum: d(11),
            license_expression: b"MIT".to_vec(),
            direct_production_dependency: true,
        }],
        provenance: BuilderProvenanceV0 {
            builder_identity_digest: d(12),
            workflow_digest: d(13),
            run_identity_digest: d(14),
            isolated_environment_digest: d(15),
            exact_source_digest: exact.canonical_digest(),
            build_inputs: vec![BuildInputV0 {
                logical_name: b"input".to_vec(),
                source_digest: d(16),
                content_digest: d(17),
            }],
            artifact_set_digest: d(18),
            sbom_digest: d(19),
            provenance_digest: d(20),
        },
        previous_bundle_digest: None,
        signer_identity_digest: Digest32V0(identity),
        signature_digest: d(21),
        bundle_digest: d(22),
    };
    b.provenance.artifact_set_digest = b.artifact_set_digest();
    b.provenance.sbom_digest = b.sbom_digest();
    b.provenance.provenance_digest = b.provenance.canonical_digest();
    b.bundle_digest = b.canonical_digest();
    b
}
#[test]
fn existing_release_bundle_path_uses_real_pq_quorum_and_provenance_checks() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let mut b = bundle(a.bundle_signer_identity(role));
    let mut m = metadata(&a, role, 20);
    m.content = b.bundle_digest.0;
    let sig = sign_metadata(&f, &m);
    b.signature_digest = Digest32V0(pq_release_signature_digest_v1(&sig).unwrap());
    let mut bad = b.clone();
    bad.provenance.exact_source_digest = Digest32V0([99; 32]);
    let before = a.checkpoint();
    assert_eq!(
        a.accept_bundle(&bad, &[], &m, &sig, 20),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    assert_eq!(a.checkpoint(), before);
    let mut bad = b.clone();
    bad.signature_digest = Digest32V0([99; 32]);
    assert_eq!(
        a.accept_bundle(&bad, &[], &m, &sig, 20),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    let (verified, receipt) = a
        .accept_bundle(&b, &[(b"node".to_vec(), b"1".to_vec())], &m, &sig, 20)
        .unwrap();
    assert_eq!(verified.bundle_digest, b.bundle_digest);
    assert_eq!(receipt.content(), b.bundle_digest.0);
}

#[test]
fn recovery_requires_complete_ordered_history_and_bound_observation_times() {
    let f = fixture(0);
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let mut events = Vec::new();
    for (content, observed_at) in [(40, 20), (41, 21)] {
        let m = metadata(&a, role, content);
        let signatures = sign_metadata(&f, &m);
        a.accept(&m, &signatures, observed_at).unwrap();
        events.push(PqReleaseEventV1::Release {
            metadata: m,
            signatures,
            observed_at,
        });
    }
    let expected = a.checkpoint();
    let recover = |events: &[PqReleaseEventV1], initialized_at| {
        PqReleaseAuthorityV1::recover_pinned(
            f.root.clone(),
            f.root.digest().unwrap(),
            initialized_at,
            events,
            expected,
        )
    };
    let mut recovered = recover(&events, 10).unwrap();
    assert_eq!(recovered.role_version(role), 2);
    assert_eq!(recovered.current_content(role), Some([41; 32]));
    assert!(matches!(
        recover(&events[..1], 10),
        Err(PqReleaseErrorV1::CheckpointConflict)
    ));
    let mut reordered = events.clone();
    reordered.reverse();
    assert!(matches!(
        recover(&reordered, 10),
        Err(PqReleaseErrorV1::CheckpointConflict)
    ));
    let mut retimed = events.clone();
    if let PqReleaseEventV1::Release { observed_at, .. } = &mut retimed[1] {
        *observed_at = 22;
    }
    assert!(matches!(
        recover(&retimed, 10),
        Err(PqReleaseErrorV1::CheckpointConflict)
    ));
    assert!(matches!(
        recover(&events, 11),
        Err(PqReleaseErrorV1::CheckpointConflict)
    ));
    let mut rollback = metadata(&recovered, role, 40);
    assert_eq!(
        recovered.accept(&rollback, &sign_metadata(&f, &rollback), 20),
        Err(PqReleaseErrorV1::ClockRollback)
    );
    assert_eq!(
        recovered.accept(&rollback, &sign_metadata(&f, &rollback), 22),
        Err(PqReleaseErrorV1::RollbackApproval)
    );
    rollback.approved_content_rollback = true;
    recovered
        .accept(&rollback, &sign_metadata(&f, &rollback), 22)
        .unwrap();
    assert_eq!(recovered.role_version(role), 3);
}

#[test]
fn recovery_retains_key_retirement_and_expired_root_cannot_authorize_content() {
    let mut f = fixture(0);
    f.root.expires_at = 30;
    let mut a = authority(&f);
    let role = PqReleaseRoleV1::NodeSoftware;
    let mut expired = metadata(&a, role, 40);
    expired.expires_at = 29;
    assert_eq!(
        a.accept(&expired, &sign_metadata(&f, &expired), 40),
        Err(PqReleaseErrorV1::Expired)
    );
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let old_signatures = signatures(&f, &f.root.offline_root, &message);
    let new_signatures = signatures(&successor, &next.offline_root, &message);
    a.rotate_root(next.clone(), &old_signatures, &new_signatures, 40)
        .unwrap();
    let events = vec![PqReleaseEventV1::RootRotation {
        root: next.clone(),
        old_signatures,
        new_signatures,
        observed_at: 40,
    }];
    let mut recovered = PqReleaseAuthorityV1::recover_pinned(
        f.root.clone(),
        f.root.digest().unwrap(),
        10,
        &events,
        a.checkpoint(),
    )
    .unwrap();
    assert_eq!(recovered.root_generation(), 2);
    assert_eq!(recovered.root_digest(), a.root_digest());
    let mut resurrect = f.root.clone();
    resurrect.generation = 3;
    resurrect.expires_at = 1000;
    resurrect.previous_root_digest = recovered.root_digest();
    let message = resurrect.signing_message().unwrap();
    assert_eq!(
        recovered.rotate_root(
            resurrect.clone(),
            &signatures(&successor, &next.offline_root, &message),
            &signatures(&f, &resurrect.offline_root, &message),
            41,
        ),
        Err(PqReleaseErrorV1::RetiredKey)
    );
    let current = metadata(&recovered, role, 41);
    recovered
        .accept(&current, &sign_metadata(&successor, &current), 41)
        .unwrap();
}

#[test]
fn live_event_quota_bounds_recovery_and_failed_updates_do_not_spend_it() {
    let f = fixture(0);
    let mut a = authority(&f);
    // Exercise the boundary without generating thousands of expensive signatures.
    // All accepted operations below still use the real native ML-DSA verifier.
    a.event_count = MAX_RECOVERY_EVENTS_V1 - 2;
    let role = PqReleaseRoleV1::NodeSoftware;
    let m = metadata(&a, role, 40);
    let signed = sign_metadata(&f, &m);
    assert_eq!(
        a.accept(&m, &signed[..1], 20),
        Err(PqReleaseErrorV1::InsufficientSignatures)
    );
    assert_eq!(a.event_count, MAX_RECOVERY_EVENTS_V1 - 2);
    a.accept(&m, &signed, 20).unwrap();
    assert_eq!(a.event_count, MAX_RECOVERY_EVENTS_V1 - 1);
    let mut next = f.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let signed = signatures(&f, &f.root.offline_root, &next.signing_message().unwrap());
    a.rotate_root(next.clone(), &signed, &signed, 21).unwrap();
    assert_eq!(a.event_count, MAX_RECOVERY_EVENTS_V1);
    let checkpoint = a.checkpoint();
    let same_content = metadata(&a, role, 40);
    assert_eq!(
        a.accept(&same_content, &sign_metadata(&f, &same_content), 22),
        Err(PqReleaseErrorV1::HistoryFull)
    );
    next.generation = 3;
    next.previous_root_digest = a.root_digest();
    let signed = signatures(&f, &f.root.offline_root, &next.signing_message().unwrap());
    assert_eq!(
        a.rotate_root(next, &signed, &signed, 22),
        Err(PqReleaseErrorV1::HistoryFull)
    );
    assert_eq!(a.checkpoint(), checkpoint);
    assert_eq!(a.root_generation(), 2);
    assert_eq!(a.role_version(role), 1);
    assert_eq!(a.current_content(role), Some([40; 32]));
    assert_eq!(a.event_count, MAX_RECOVERY_EVENTS_V1);
}

#[test]
fn old_software_bundle_can_be_reapproved_after_root_rotation_only_by_current_quorum() {
    let first = fixture(0);
    let mut a = authority(&first);
    let role = PqReleaseRoleV1::NodeSoftware;
    let identity = a.bundle_signer_identity(role);
    let mut old_bundle = bundle(identity);
    let mut m = metadata(&a, role, 40);
    m.content = old_bundle.bundle_digest.0;
    let signed = sign_metadata(&first, &m);
    old_bundle.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signed).unwrap());
    a.accept_bundle(&old_bundle, &[], &m, &signed, 20).unwrap();
    let mut newer_bundle = bundle(identity);
    newer_bundle.release_version = b"2".to_vec();
    newer_bundle.previous_bundle_digest = Some(old_bundle.bundle_digest);
    newer_bundle.artifacts[0].content_digest = Digest32V0([80; 32]);
    newer_bundle.provenance.artifact_set_digest = newer_bundle.artifact_set_digest();
    newer_bundle.provenance.provenance_digest = newer_bundle.provenance.canonical_digest();
    newer_bundle.bundle_digest = newer_bundle.canonical_digest();
    let mut m = metadata(&a, role, 41);
    m.content = newer_bundle.bundle_digest.0;
    let signed = sign_metadata(&first, &m);
    newer_bundle.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signed).unwrap());
    a.accept_bundle(&newer_bundle, &[], &m, &signed, 21)
        .unwrap();

    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    a.rotate_root(
        next.clone(),
        &signatures(&first, &first.root.offline_root, &message),
        &signatures(&successor, &next.offline_root, &message),
        22,
    )
    .unwrap();
    assert_eq!(a.bundle_signer_identity(role), identity);
    let mut rollback = metadata(&a, role, 40);
    rollback.content = old_bundle.bundle_digest.0;
    rollback.approved_content_rollback = true;
    let stale_keys = sign_metadata(&first, &rollback);
    old_bundle.signature_digest = Digest32V0(pq_release_signature_digest_v1(&stale_keys).unwrap());
    let before = a.checkpoint();
    assert_eq!(
        a.accept_bundle(&old_bundle, &[], &rollback, &stale_keys, 23),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    assert_eq!(a.checkpoint(), before);
    let fresh = sign_metadata(&successor, &rollback);
    old_bundle.signature_digest = Digest32V0(pq_release_signature_digest_v1(&fresh).unwrap());
    let (verified, receipt) = a
        .accept_bundle(&old_bundle, &[], &rollback, &fresh, 23)
        .unwrap();
    assert_eq!(verified.bundle_digest, old_bundle.bundle_digest);
    assert_eq!(receipt.content(), old_bundle.bundle_digest.0);
    assert_eq!(receipt.version(), 3);
    assert_eq!(a.root_generation(), 2);
}

#[test]
fn activation_requires_live_current_generation_manifest() {
    let f = fixture(0);
    let mut a = authority(&f);
    let mut manifest = metadata(&a, PqReleaseRoleV1::CellManifest, 40);
    manifest.expires_at = 30;
    let manifest_signatures = sign_metadata(&f, &manifest);
    a.accept(&manifest, &manifest_signatures, 20).unwrap();
    let before = a.checkpoint();
    let activation = metadata(&a, PqReleaseRoleV1::CellActivation, 40);
    let activation_signatures = sign_metadata(&f, &activation);
    // An activation quorum cannot extend the other role's publication lease.
    assert_eq!(
        a.accept(&activation, &activation_signatures, 30),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.role_version(PqReleaseRoleV1::CellActivation), 0);
    assert_eq!(a.time_floor, 20);
    assert_eq!(a.event_count, 1);

    // Reconstructing the journal preserves the publication expiry as well.
    let events = [PqReleaseEventV1::Release {
        metadata: manifest,
        signatures: manifest_signatures,
        observed_at: 20,
    }];
    let mut recovered = PqReleaseAuthorityV1::recover_pinned(
        f.root.clone(),
        f.root.digest().unwrap(),
        10,
        &events,
        before,
    )
    .unwrap();
    assert_eq!(
        recovered.accept(&activation, &activation_signatures, 31),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    assert_eq!(recovered.checkpoint(), before);
    // The publisher can renew the same bytes at a higher role version.
    let renewed = metadata(&recovered, PqReleaseRoleV1::CellManifest, 40);
    recovered
        .accept(&renewed, &sign_metadata(&f, &renewed), 31)
        .unwrap();
    let fresh_activation = metadata(&recovered, PqReleaseRoleV1::CellActivation, 40);
    recovered
        .accept(&fresh_activation, &sign_metadata(&f, &fresh_activation), 31)
        .unwrap();
    assert_eq!(recovered.role_version(PqReleaseRoleV1::CellManifest), 2);
    assert_eq!(recovered.role_version(PqReleaseRoleV1::CellActivation), 1);
}

#[test]
fn activation_after_root_rotation_requires_current_manifest_quorum() {
    let f = fixture(0);
    let mut a = authority(&f);
    let manifest = metadata(&a, PqReleaseRoleV1::CellManifest, 40);
    let manifest_signatures = sign_metadata(&f, &manifest);
    a.accept(&manifest, &manifest_signatures, 20).unwrap();
    let successor = fixture(20);
    let mut next = successor.root.clone();
    next.generation = 2;
    next.previous_root_digest = a.root_digest();
    let message = next.signing_message().unwrap();
    let old_signatures = signatures(&f, &f.root.offline_root, &message);
    let new_signatures = signatures(&successor, &next.offline_root, &message);
    a.rotate_root(next.clone(), &old_signatures, &new_signatures, 21)
        .unwrap();
    let before = a.checkpoint();
    let activation = metadata(&a, PqReleaseRoleV1::CellActivation, 40);
    let activation_signatures = sign_metadata(&successor, &activation);
    // Current activation keys cannot substitute for current publisher keys.
    assert_eq!(
        a.accept(&activation, &activation_signatures, 22),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    assert_eq!(a.checkpoint(), before);
    assert_eq!(a.role_version(PqReleaseRoleV1::CellActivation), 0);
    assert_eq!(a.time_floor, 21);
    assert_eq!(a.event_count, 2);
    let events = [
        PqReleaseEventV1::Release {
            metadata: manifest,
            signatures: manifest_signatures,
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
        before,
    )
    .unwrap();
    assert_eq!(
        recovered.accept(&activation, &activation_signatures, 22),
        Err(PqReleaseErrorV1::UnpublishedActivation)
    );
    assert_eq!(recovered.checkpoint(), before);
    let renewed = metadata(&recovered, PqReleaseRoleV1::CellManifest, 40);
    assert_eq!(
        recovered.accept(&renewed, &sign_metadata(&f, &renewed), 22),
        Err(PqReleaseErrorV1::UnknownSigner)
    );
    recovered
        .accept(&renewed, &sign_metadata(&successor, &renewed), 22)
        .unwrap();
    let fresh_activation = metadata(&recovered, PqReleaseRoleV1::CellActivation, 40);
    recovered
        .accept(
            &fresh_activation,
            &sign_metadata(&successor, &fresh_activation),
            22,
        )
        .unwrap();
    assert_eq!(recovered.role_version(PqReleaseRoleV1::CellManifest), 2);
    assert_eq!(recovered.role_version(PqReleaseRoleV1::CellActivation), 1);
}
