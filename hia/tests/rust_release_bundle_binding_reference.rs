// Prefix supplied by Python: original ReleaseBundle V0 implementation, original
// fixture builders and the independently implemented SHA-256 test seam.
struct StopAtSignature;

impl ReleaseSignatureVerifierV0 for StopAtSignature {
    type Error = io::Error;

    fn verify_release_signature(&self, _: &ReleaseBundleV0) -> Result<(), Self::Error> {
        Err(io::Error::other("signature verification deliberately not executed"))
    }
}

fn bind_provenance(bundle: &mut ReleaseBundleV0) {
    bundle.provenance.exact_source_digest = bundle.exact_source.canonical_digest();
    bundle.provenance.artifact_set_digest = bundle.artifact_set_digest();
    bundle.provenance.sbom_digest = bundle.sbom_digest();
    bundle.provenance.provenance_digest = bundle.provenance.canonical_digest();
}

fn emit(bundle: &ReleaseBundleV0, stage: u8, out: &mut impl Write) -> io::Result<()> {
    let (status, canonical) = match verify_release_bundle_v0(
        &StopAtSignature,
        bundle,
        &[(b"trnm-portable-node".to_vec(), b"0.1.0".to_vec())],
    ) {
        Err(ReleaseBundleHostErrorV0::Signature(err)) => {
            assert_eq!(err.to_string(), "signature verification deliberately not executed");
            assert_eq!(stage, 0);
            (0, bundle.canonical_digest())
        }
        Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidExactSource)) => {
            assert_eq!(stage, 1);
            (101, d(0))
        }
        Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::ProvenanceBindingMismatch)) => {
            assert!(matches!(stage, 2 | 3));
            (104, d(0))
        }
        Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidBundle)) if stage == 4 => {
            // This case checks the canonical function after intentionally
            // violating upstream admission. Arithmetic binding is not admission.
            (0, bundle.canonical_digest())
        }
        other => panic!("unexpected original bundle result: {other:?}"),
    };
    let source = bundle.exact_source;
    let mut frame = Vec::new();
    for value in [
        source.repository_digest,
        source.commit_digest,
        source.tree_digest,
        source.cargo_lock_digest,
        source.toolchain_digest,
        source.production_closure_digest,
    ] {
        frame.extend_from_slice(&value.0);
    }
    frame.push(u8::from(source.dirty));
    for value in [
        bundle.protocol_digest,
        bundle.artifact_set_digest(),
        bundle.sbom_digest(),
        bundle.provenance.provenance_digest,
        bundle.previous_bundle_digest.unwrap_or(d(0)),
        bundle.signer_identity_digest,
        bundle.provenance.exact_source_digest,
        bundle.provenance.artifact_set_digest,
        bundle.provenance.sbom_digest,
        bundle.bundle_digest,
    ] {
        frame.extend_from_slice(&value.0);
    }
    for field in [&bundle.bundle_name, &bundle.release_version] {
        frame.extend_from_slice(&u16::try_from(field.len()).unwrap().to_le_bytes());
    }
    frame.extend_from_slice(&bundle.bundle_name);
    frame.extend_from_slice(&bundle.release_version);

    out.write_all(&[status, stage])?;
    out.write_all(&u16::try_from(frame.len()).unwrap().to_le_bytes())?;
    out.write_all(&canonical.0)?;
    out.write_all(&frame)
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    let base = bundle(20, 7);
    emit(&base, 0, &mut out)?;
    for field in 0..6 {
        let mut zero = base.clone();
        match field {
            0 => zero.exact_source.repository_digest = d(0),
            1 => zero.exact_source.commit_digest = d(0),
            2 => zero.exact_source.tree_digest = d(0),
            3 => zero.exact_source.cargo_lock_digest = d(0),
            4 => zero.exact_source.toolchain_digest = d(0),
            5 => zero.exact_source.production_closure_digest = d(0),
            _ => unreachable!(),
        }
        emit(&zero, 1, &mut out)?;
    }
    let mut dirty = base.clone();
    dirty.exact_source.dirty = true;
    dirty.bundle_digest = d(0);
    emit(&dirty, 1, &mut out)?;

    for (name, version) in [(1, 1), (255, 127), (256, 128), (511, 255), (512, 256)] {
        let mut boundary = base.clone();
        boundary.bundle_name = vec![b'A'; name];
        boundary.release_version = vec![b'Z'; version];
        boundary.bundle_digest = boundary.canonical_digest();
        emit(&boundary, 0, &mut out)?;
    }
    let mut not_a_valid_bundle = base.clone();
    not_a_valid_bundle.bundle_name.clear();
    not_a_valid_bundle.release_version = vec![0xff, 0, b'!'];
    not_a_valid_bundle.bundle_digest = not_a_valid_bundle.canonical_digest();
    emit(&not_a_valid_bundle, 4, &mut out)?;

    let mut prior_zero = base.clone();
    prior_zero.previous_bundle_digest = Some(d(0));
    assert_eq!(base.canonical_digest(), prior_zero.canonical_digest());
    emit(&prior_zero, 0, &mut out)?;
    let mut signature_only = base.clone();
    signature_only.signature_digest = d(222);
    assert_eq!(base.canonical_digest(), signature_only.canonical_digest());
    emit(&signature_only, 0, &mut out)?;

    // The last octet of each link flips. Update the provenance digest so all
    // three cases really reach the original final binding branch.
    for link in 0..3 {
        let mut forged_binding = base.clone();
        let value = match link {
            0 => &mut forged_binding.provenance.exact_source_digest,
            1 => &mut forged_binding.provenance.artifact_set_digest,
            2 => &mut forged_binding.provenance.sbom_digest,
            _ => unreachable!(),
        };
        value.0[31] ^= 0x80;
        forged_binding.provenance.provenance_digest = forged_binding.provenance.canonical_digest();
        forged_binding.bundle_digest = forged_binding.canonical_digest();
        emit(&forged_binding, 2, &mut out)?;
    }
    let mut bad_release = base.clone();
    bad_release.bundle_digest.0[31] ^= 0x80;
    emit(&bad_release, 3, &mut out)?;

    for field in 0..9 {
        let mut updated = base.clone();
        match field {
            0 => updated.bundle_name.push(b'!'),
            1 => updated.release_version.push(b'!'),
            2 => updated.protocol_digest.0[31] ^= 0x80,
            3 => updated.exact_source.repository_digest.0[31] ^= 0x80,
            4 => updated.artifacts[0].content_digest.0[31] ^= 0x80,
            5 => updated.sbom_packages[0].package_checksum.0[31] ^= 0x80,
            6 => updated.provenance.builder_identity_digest.0[31] ^= 0x80,
            7 => updated.previous_bundle_digest = Some(d(241)),
            8 => updated.signer_identity_digest.0[31] ^= 0x80,
            _ => unreachable!(),
        }
        bind_provenance(&mut updated);
        emit(&updated, 3, &mut out)?;
        updated.bundle_digest = updated.canonical_digest();
        assert_ne!(updated.bundle_digest, base.bundle_digest);
        emit(&updated, 0, &mut out)?;
    }
    Ok(())
}
