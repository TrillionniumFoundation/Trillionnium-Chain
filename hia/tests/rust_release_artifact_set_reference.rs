// The harness prefixes the unmodified V0 methods and fixture plus a SHA-256
// adapter. The signature seam always refuses; this is not release admission.
use std::io::Read;

struct StopAtSignature;
impl ReleaseSignatureVerifierV0 for StopAtSignature {
    type Error = io::Error;

    fn verify_release_signature(&self, _: &ReleaseBundleV0) -> Result<(), Self::Error> {
        Err(io::Error::other("signature boundary reached"))
    }
}

fn text(slot: &[u8], width_at: usize, begin: usize) -> Vec<u8> {
    let size = u16::from_le_bytes(slot[width_at..width_at + 2].try_into().unwrap()) as usize;
    slot[begin..begin + size].to_vec()
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut feed = input.as_slice();
    let mut out = io::stdout().lock();
    while !feed.is_empty() {
        let mode = feed[0];
        let rows = u16::from_le_bytes(feed[1..3].try_into().unwrap()) as usize;
        let end = 3 + 877 * rows;
        let mut release = bundle(20, 7);
        release.artifacts = feed[3..end]
            .chunks_exact(877)
            .map(|slot| ArtifactEntryV0 {
                logical_name: text(slot, 0, 109),
                media_type: text(slot, 2, 621),
                size_bytes: u64::from_le_bytes(slot[4..12].try_into().unwrap()),
                content_digest: Digest32V0(slot[13..45].try_into().unwrap()),
                executable: match slot[12] {
                    0 => false,
                    1 => true,
                    _ => panic!("not a typed Boolean"),
                },
                platform_digest: Digest32V0(slot[45..77].try_into().unwrap()),
                source_path_digest: Digest32V0(slot[77..109].try_into().unwrap()),
            })
            .collect();
        let digest = release.artifact_set_digest();
        let code = match mode {
            0 => 0,
            1 => {
                release.provenance.artifact_set_digest = digest;
                release.provenance.provenance_digest = release.provenance.canonical_digest();
                release.bundle_digest = release.canonical_digest();
                match verify_release_bundle_v0(&StopAtSignature, &release, &[]) {
                    Err(ReleaseBundleHostErrorV0::Signature(reason)) => {
                        assert_eq!(reason.to_string(), "signature boundary reached");
                        0
                    }
                    Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidBundle)) => {
                        assert!(release.artifacts.is_empty());
                        105
                    }
                    Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::InvalidArtifact)) => {
                        106
                    }
                    Err(ReleaseBundleHostErrorV0::Protocol(ReleaseBundleErrorV0::DuplicateArtifact)) => {
                        107
                    }
                    other => panic!("unexpected V0 verifier result: {other:?}"),
                }
            }
            _ => unreachable!(),
        };
        out.write_all(&[code])?;
        if code == 0 {
            out.write_all(&digest.0)?;
            release.artifacts.sort_unstable();
            for row in release.artifacts {
                out.write_all(&row.canonical_digest().0)?;
            }
        }
        feed = &feed[end..];
    }
    Ok(())
}
