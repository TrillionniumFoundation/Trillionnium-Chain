// The harness prefixes the exact original V0 code, fixture and independent
// SHA-256 seam. Reaching the signature callback is an intentional hard error.
use std::io::Read;

struct StopAtSignature;
impl ReleaseSignatureVerifierV0 for StopAtSignature {
    type Error = io::Error;

    fn verify_release_signature(&self, _: &ReleaseBundleV0) -> Result<(), Self::Error> {
        Err(io::Error::other("unsigned reference reached original signature boundary"))
    }
}

fn le16(data: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(data[at..at + 2].try_into().unwrap()))
}

fn vec_field(slot: &[u8], length_at: usize, data_at: usize) -> Vec<u8> {
    let count = le16(slot, length_at);
    slot[data_at..data_at + count].to_vec()
}

fn digest(data: &[u8], at: usize) -> Digest32V0 {
    Digest32V0(data[at..at + 32].try_into().unwrap())
}

fn boolean(value: u8) -> bool {
    match value {
        0 => false,
        1 => true,
        _ => panic!("invalid typed Boolean in the original differential"),
    }
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut frame = raw.as_slice();
    let mut out = io::stdout().lock();
    while !frame.is_empty() {
        let art_begin = 1067;
        let sbom_begin = art_begin + 877 * le16(frame, 4);
        let key_begin = sbom_begin + 1351 * le16(frame, 6);
        let end = key_begin + 772 * le16(frame, 8);
        let mut release = bundle(20, 7);
        release.bundle_name = vec_field(frame, 0, 299);
        release.release_version = vec_field(frame, 2, 811);
        release.protocol_digest = digest(frame, 10);
        release.signer_identity_digest = digest(frame, 42);
        release.signature_digest = digest(frame, 74);
        release.exact_source = ExactSourceV0 {
            repository_digest: digest(frame, 106),
            commit_digest: digest(frame, 138),
            tree_digest: digest(frame, 170),
            cargo_lock_digest: digest(frame, 202),
            toolchain_digest: digest(frame, 234),
            production_closure_digest: digest(frame, 266),
            dirty: boolean(frame[298]),
        };
        release.artifacts = frame[art_begin..sbom_begin]
            .chunks_exact(877)
            .map(|r| ArtifactEntryV0 {
                logical_name: vec_field(r, 0, 109),
                media_type: vec_field(r, 2, 621),
                size_bytes: u64::from_le_bytes(r[4..12].try_into().unwrap()),
                content_digest: digest(r, 13),
                executable: boolean(r[12]),
                platform_digest: digest(r, 45),
                source_path_digest: digest(r, 77),
            })
            .collect();
        release.sbom_packages = frame[sbom_begin..key_begin]
            .chunks_exact(1351)
            .map(|r| SbomPackageV0 {
                package_name: vec_field(r, 0, 71),
                package_version: vec_field(r, 2, 583),
                source_digest: digest(r, 7),
                package_checksum: digest(r, 39),
                license_expression: vec_field(r, 4, 839),
                direct_production_dependency: boolean(r[6]),
            })
            .collect();
        let required: Vec<_> = frame[key_begin..end]
            .chunks_exact(772)
            .map(|r| (vec_field(r, 0, 4), vec_field(r, 2, 516)))
            .collect();

        let count = le16(frame, end);
        let fixed = end + 2;
        let rows = end + 322;
        let full_end = rows + 578 * count;
        release.provenance.builder_identity_digest = digest(frame, fixed);
        release.provenance.workflow_digest = digest(frame, fixed + 32);
        release.provenance.run_identity_digest = digest(frame, fixed + 64);
        release.provenance.isolated_environment_digest = digest(frame, fixed + 96);
        release.provenance.exact_source_digest = digest(frame, fixed + 128);
        release.provenance.artifact_set_digest = digest(frame, fixed + 160);
        release.provenance.sbom_digest = digest(frame, fixed + 192);
        release.provenance.provenance_digest = digest(frame, fixed + 224);
        let previous = digest(frame, fixed + 256);
        release.previous_bundle_digest = (previous != Digest32V0([0; 32])).then_some(previous);
        release.bundle_digest = digest(frame, fixed + 288);
        release.provenance.build_inputs = frame[rows..full_end]
            .chunks_exact(578)
            .map(|row| BuildInputV0 {
                logical_name: vec_field(row, 0, 66),
                source_digest: digest(row, 2),
                content_digest: digest(row, 34),
            })
            .collect();

        let code = match verify_release_bundle_v0(&StopAtSignature, &release, &required) {
            Err(ReleaseBundleHostErrorV0::Signature(err)) => {
                assert_eq!(err.to_string(), "unsigned reference reached original signature boundary");
                0
            }
            Err(ReleaseBundleHostErrorV0::Protocol(error)) => match error {
                ReleaseBundleErrorV0::InvalidBundle => 110,
                ReleaseBundleErrorV0::InvalidExactSource => 101,
                ReleaseBundleErrorV0::InvalidArtifact => 106,
                ReleaseBundleErrorV0::DuplicateArtifact => 107,
                ReleaseBundleErrorV0::InvalidSbomPackage => 116,
                ReleaseBundleErrorV0::DuplicateSbomPackage => 117,
                ReleaseBundleErrorV0::IncompleteSbom => 108,
                ReleaseBundleErrorV0::InvalidProvenance => 105,
                ReleaseBundleErrorV0::InvalidBuildInput => 126,
                ReleaseBundleErrorV0::DuplicateBuildInput => 127,
                ReleaseBundleErrorV0::ProvenanceBindingMismatch => 104,
            },
            other => panic!("unexpected original result: {other:?}"),
        };
        out.write_all(&[code])?;
        if code == 0 {
            out.write_all(&release.canonical_digest().0)?;
            out.write_all(&release.exact_source.canonical_digest().0)?;
            out.write_all(&release.artifact_set_digest().0)?;
            out.write_all(&release.sbom_digest().0)?;
            out.write_all(&release.provenance.canonical_digest().0)?;
            out.write_all(&(release.artifacts.len() as u32).to_le_bytes())?;
            out.write_all(&(release.sbom_packages.len() as u32).to_le_bytes())?;
        }
        frame = &frame[full_end..];
    }
    Ok(())
}
