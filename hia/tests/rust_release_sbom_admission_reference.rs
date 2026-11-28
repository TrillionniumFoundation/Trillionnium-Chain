// The harness prefixes the unmodified V0 verification and digest methods
// plus the independent SHA-256 seam. This callback never approves a release.
use std::io::Read;

struct AtSignature;

impl ReleaseSignatureVerifierV0 for AtSignature {
    type Error = io::Error;

    fn verify_release_signature(&self, _: &ReleaseBundleV0) -> Result<(), Self::Error> {
        Err(io::Error::other("original signature boundary reached"))
    }
}

fn text(slot: &[u8], length_at: usize, data_at: usize) -> Vec<u8> {
    let count = usize::from(u16::from_le_bytes(slot[length_at..length_at + 2].try_into().unwrap()));
    slot[data_at..data_at + count].to_vec()
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = raw.as_slice();
    let mut out = io::stdout().lock();
    while !input.is_empty() {
        let count = usize::from(u16::from_le_bytes(input[..2].try_into().unwrap()));
        let pkgs_end = 2 + count * 1351;
        let nkeys = usize::from(u16::from_le_bytes(input[pkgs_end..pkgs_end + 2].try_into().unwrap()));
        let end = pkgs_end + 2 + nkeys * 772;
        let required: Vec<_> = input[pkgs_end + 2..end]
            .chunks_exact(772)
            .map(|slot| (text(slot, 0, 4), text(slot, 2, 516)))
            .collect();
        let mut candidate = bundle(20, 7);
        candidate.sbom_packages = input[2..pkgs_end]
            .chunks_exact(1351)
            .map(|slot| SbomPackageV0 {
                package_name: text(slot, 0, 71),
                package_version: text(slot, 2, 583),
                source_digest: Digest32V0(slot[7..39].try_into().unwrap()),
                package_checksum: Digest32V0(slot[39..71].try_into().unwrap()),
                license_expression: text(slot, 4, 839),
                direct_production_dependency: match slot[6] {
                    0 => false,
                    1 => true,
                    _ => panic!("untyped package flag"),
                },
            })
            .collect();
        candidate.provenance.sbom_digest = candidate.sbom_digest();
        candidate.provenance.provenance_digest = candidate.provenance.canonical_digest();
        candidate.bundle_digest = candidate.canonical_digest();

        let code = match verify_release_bundle_v0(&AtSignature, &candidate, &required) {
            Err(ReleaseBundleHostErrorV0::Signature(err)) => {
                assert_eq!(err.to_string(), "original signature boundary reached");
                0
            }
            Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidBundle)) => {
                assert!(candidate.sbom_packages.is_empty());
                105
            }
            Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidSbomPackage)) => 106,
            Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::DuplicateSbomPackage)) => 107,
            Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::IncompleteSbom)) => 108,
            other => panic!("unexpected original result: {other:?}"),
        };
        out.write_all(&[code])?;
        if code == 0 {
            out.write_all(&candidate.sbom_digest().0)?;
            candidate.sbom_packages.sort_unstable();
            for package in candidate.sbom_packages {
                out.write_all(&package.canonical_digest().0)?;
            }
        }
        input = &input[end..];
    }
    Ok(())
}
