//! Locked original public artifact aggregate only; no release verification.
use std::io::{self, Read, Write};
use trnm_release_bundle::{ArtifactEntryV0, BuilderProvenanceV0, Digest32V0,
    ExactSourceV0, ReleaseBundleV0};
const ZERO: Digest32V0 = Digest32V0([0;32]);

fn short(data: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(data[at..at+2].try_into().unwrap()))
}
fn field(data: &[u8], at: usize) -> Digest32V0 {
    Digest32V0(data[at..at+32].try_into().unwrap())
}
fn main() -> io::Result<()> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let mut p = data.as_slice();
    let mut out = io::stdout().lock();
    while !p.is_empty() {
        let stop = 2 + 877 * short(p,0);
        let artifacts = p[2..stop].chunks_exact(877).map(|r| ArtifactEntryV0 {
            logical_name:r[109..109+short(r,0)].to_vec(),
            media_type:r[621..621+short(r,2)].to_vec(),
            size_bytes:u64::from_le_bytes(r[4..12].try_into().unwrap()),
            content_digest:field(r,13), executable: match r[12] {0=>false,1=>true,_=>panic!("bad type")},
            platform_digest:field(r,45), source_path_digest:field(r,77),
        }).collect();
        let b = ReleaseBundleV0 {
            bundle_name:vec![],release_version:vec![],protocol_digest:ZERO,
            exact_source:ExactSourceV0 {
                repository_digest:ZERO,commit_digest:ZERO,tree_digest:ZERO,
                cargo_lock_digest:ZERO,toolchain_digest:ZERO,production_closure_digest:ZERO,dirty:false,
            },
            artifacts, sbom_packages:vec![],
            provenance:BuilderProvenanceV0 {
                builder_identity_digest:ZERO,workflow_digest:ZERO,run_identity_digest:ZERO,
                isolated_environment_digest:ZERO,exact_source_digest:ZERO,artifact_set_digest:ZERO,
                sbom_digest:ZERO,provenance_digest:ZERO,build_inputs:vec![],
            },
            previous_bundle_digest:None,signer_identity_digest:ZERO,signature_digest:ZERO,bundle_digest:ZERO,
        };
        out.write_all(&b.artifact_set_digest().0)?;
        p=&p[stop..];
    }
    Ok(())
}
