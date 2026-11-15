use super::*;

fn signed_bundle(
    f: &Fixture,
    a: &PqReleaseAuthorityV1,
) -> (
    ReleaseBundleV0,
    PqReleaseMetadataV1,
    Vec<PqReleaseSignatureV1>,
) {
    let mut b = bundle(a.bundle_signer_identity(PqReleaseRoleV1::NodeSoftware));
    let mut m = metadata(a, PqReleaseRoleV1::NodeSoftware, 20);
    m.content = b.bundle_digest.0;
    let signatures = sign_metadata(f, &m);
    b.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signatures).unwrap());
    (b, m, signatures)
}

fn observation<'a>(
    a: &PqReleaseAuthorityV1,
    b: &ReleaseBundleV0,
    m: &'a PqReleaseMetadataV1,
    signatures: &'a [PqReleaseSignatureV1],
) -> VerifiedBundleQuorumV1<'a> {
    let verifier = BoundPqBundleVerifierV1::new(a, m, signatures).unwrap();
    verify_release_bundle_v0(&verifier, b, &[]).unwrap();
    verifier.into_verified_quorum().unwrap()
}

#[test]
fn bundle_quorum_keeps_signature_failure_before_owner_time_failure() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let (b, m, signatures) = signed_bundle(&f, &a);
    let mut corrupt = signatures.clone();
    corrupt[0].signature[22] ^= 1;
    let mut bad = b.clone();
    bad.signature_digest = Digest32V0(pq_release_signature_digest_v1(&corrupt).unwrap());
    for now in [9, 1000] {
        assert_eq!(
            a.accept_bundle(&bad, &[], &m, &corrupt, now),
            Err(PqReleaseErrorV1::InvalidBundle)
        );
    }
    assert_eq!(
        a.accept_bundle(&b, &[], &m, &signatures, 9),
        Err(PqReleaseErrorV1::ClockRollback)
    );
    assert_eq!(
        a.accept_bundle(&b, &[], &m, &signatures, 1000),
        Err(PqReleaseErrorV1::Expired)
    );
    assert_eq!(a.checkpoint(), before);
}

#[test]
fn bundle_quorum_keeps_v0_content_and_exact_signed_message_binding() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let (b, m, signatures) = signed_bundle(&f, &a);
    let mut bad = b.clone();
    bad.provenance.exact_source_digest = Digest32V0([99; 32]);
    assert_eq!(
        a.accept_bundle(&bad, &[], &m, &signatures, 20),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    assert_eq!(
        a.accept_bundle(
            &b,
            &[(b"missing".to_vec(), b"1".to_vec())],
            &m,
            &signatures,
            20
        ),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    let mut altered = m.clone();
    altered.expires_at -= 1;
    assert_eq!(
        a.accept_bundle(&b, &[], &altered, &signatures, 20),
        Err(PqReleaseErrorV1::InvalidBundle)
    );
    altered = m.clone();
    altered.role = PqReleaseRoleV1::CellManifest;
    assert_eq!(
        a.accept_bundle(&b, &[], &altered, &signatures, 20),
        Err(PqReleaseErrorV1::BundleBinding)
    );
    assert_eq!(a.checkpoint(), before);
}

#[test]
fn bundle_quorum_still_checks_current_owner_state_after_valid_signature() {
    let f = fixture(0);
    let mut a = authority(&f);
    let before = a.checkpoint();
    let (b, m, _) = signed_bundle(&f, &a);
    let mut cases = Vec::new();
    let mut altered = m.clone();
    altered.network_id = [99; 32];
    cases.push((altered, PqReleaseErrorV1::WrongAuthority));
    altered = m.clone();
    altered.root_generation += 1;
    cases.push((altered, PqReleaseErrorV1::WrongAuthority));
    altered = m.clone();
    altered.expected_checkpoint = [99; 32];
    cases.push((altered, PqReleaseErrorV1::CheckpointConflict));
    altered = m.clone();
    altered.role_version += 1;
    cases.push((altered, PqReleaseErrorV1::VersionRollback));
    altered = m.clone();
    altered.expires_at = 1001;
    cases.push((altered, PqReleaseErrorV1::Expired));
    for (altered, expected) in cases {
        let signatures = sign_metadata(&f, &altered);
        let mut b = b.clone();
        b.signature_digest = Digest32V0(pq_release_signature_digest_v1(&signatures).unwrap());
        assert_eq!(
            a.accept_bundle(&b, &[], &altered, &signatures, 20),
            Err(expected)
        );
        assert_eq!(a.checkpoint(), before);
    }
}

#[test]
fn bundle_quorum_observation_is_bound_to_root_role_message_and_signature_bytes() {
    let f = fixture(0);
    let a = authority(&f);
    let (b, m, signatures) = signed_bundle(&f, &a);
    let message = m.signing_message();
    for change in 0..5 {
        let proof = observation(&a, &b, &m, &signatures);
        let mut root = a.root_digest();
        let mut role = m.role;
        let mut message = message.clone();
        let mut supplied = signatures.clone();
        match change {
            0 => root[0] ^= 1,
            1 => role = PqReleaseRoleV1::CellManifest,
            2 => message[0] ^= 1,
            3 => supplied[0].key_id[0] ^= 1,
            4 => supplied[0].signature[22] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            proof.consume(root, role, &message, &supplied),
            Err(PqReleaseErrorV1::SignatureRejected)
        );
    }
    observation(&a, &b, &m, &signatures)
        .consume(a.root_digest(), m.role, &message, &signatures)
        .unwrap();
}

#[test]
fn bundle_quorum_failed_or_missing_callback_never_retains_an_observation() {
    let f = fixture(0);
    let a = authority(&f);
    let (b, m, signatures) = signed_bundle(&f, &a);
    assert_eq!(
        BoundPqBundleVerifierV1::new(&a, &m, &signatures)
            .unwrap()
            .into_verified_quorum()
            .err(),
        Some(PqReleaseErrorV1::InvalidBundle)
    );
    let verifier = BoundPqBundleVerifierV1::new(&a, &m, &signatures).unwrap();
    verifier.verify_release_signature(&b).unwrap();
    let mut changed = b.clone();
    changed.signature_digest = Digest32V0([99; 32]);
    assert_eq!(
        verifier.verify_release_signature(&changed),
        Err(PqReleaseErrorV1::BundleBinding)
    );
    assert_eq!(
        verifier.into_verified_quorum().err(),
        Some(PqReleaseErrorV1::InvalidBundle)
    );
}

#[test]
fn bundle_quorum_keeps_public_accept_verification_and_one_checkpoint_advance() {
    let f = fixture(0);
    let mut direct = authority(&f);
    let mut bundled = authority(&f);
    let (b, m, signatures) = signed_bundle(&f, &direct);
    let mut corrupt = signatures.clone();
    corrupt[0].signature[22] ^= 1;
    assert_eq!(
        direct.accept(&m, &corrupt, 20),
        Err(PqReleaseErrorV1::SignatureRejected)
    );
    let expected = direct.accept(&m, &signatures, 20).unwrap();
    let (verified_bundle, actual) = bundled.accept_bundle(&b, &[], &m, &signatures, 20).unwrap();
    assert_eq!(verified_bundle.bundle_digest, b.bundle_digest);
    assert_eq!(actual, expected);
    assert_eq!(bundled.checkpoint(), direct.checkpoint());
    assert_eq!(
        bundled.accept_bundle(&b, &[], &m, &signatures, 21),
        Err(PqReleaseErrorV1::CheckpointConflict)
    );
    assert_eq!(
        bundled.check_current(m.role, m.content, bundled.checkpoint(), m.expires_at),
        Err(PqReleaseErrorV1::Expired)
    );
    assert_eq!(bundled.checkpoint(), direct.checkpoint());
}
