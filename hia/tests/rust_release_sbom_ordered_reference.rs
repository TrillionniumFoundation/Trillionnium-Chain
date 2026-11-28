//! Public original SBOM digest of inert synthetic sets; no verifier/signature.
use std::io::{self, Read, Write};
use trnm_release_bundle::{BuilderProvenanceV0, Digest32V0, ExactSourceV0,
    ReleaseBundleV0, SbomPackageV0};

const ZERO: Digest32V0 = Digest32V0([0;32]);
fn small(wire: &[u8], i: usize) -> usize {
    u16::from_le_bytes(wire[i..i+2].try_into().unwrap()) as usize
}
fn bytes(wire: &[u8], width: usize, at: usize) -> Vec<u8> {
    wire[at..at+small(wire,width)].to_vec()
}
fn field(wire: &[u8], at: usize) -> Digest32V0 {
    Digest32V0(wire[at..at+32].try_into().unwrap())
}

fn main() -> io::Result<()> {
    let mut data=Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let mut packet=data.as_slice();
    let mut out=io::stdout().lock();
    while !packet.is_empty() {
        let count=small(packet,0);
        let end=2+1351*count;
        let rows=packet[2..end].chunks_exact(1351).map(|r| SbomPackageV0 {
            package_name:bytes(r,0,71),
            package_version:bytes(r,2,583),
            source_digest:field(r,7),
            package_checksum:field(r,39),
            license_expression:bytes(r,4,839),
            direct_production_dependency: match r[6] { 0=>false,1=>true,_=>panic!("untyped fixture") },
        }).collect();
        // Unrelated fields are intentionally inert. Only the original SBOM
        // value method is called, not release admission or provenance.
        let bundle=ReleaseBundleV0 {
            bundle_name:vec![],release_version:vec![],protocol_digest:ZERO,
            exact_source:ExactSourceV0 {
                repository_digest:ZERO,commit_digest:ZERO,tree_digest:ZERO,
                cargo_lock_digest:ZERO,toolchain_digest:ZERO,production_closure_digest:ZERO,dirty:false,
            },
            artifacts:vec![], sbom_packages:rows,
            provenance:BuilderProvenanceV0 {
                builder_identity_digest:ZERO,workflow_digest:ZERO,run_identity_digest:ZERO,
                isolated_environment_digest:ZERO,exact_source_digest:ZERO,artifact_set_digest:ZERO,
                sbom_digest:ZERO,provenance_digest:ZERO,build_inputs:vec![],
            },
            previous_bundle_digest:None,signer_identity_digest:ZERO,signature_digest:ZERO,bundle_digest:ZERO,
        };
        out.write_all(&bundle.sbom_digest().0)?;
        packet=&packet[end..];
    }
    Ok(())
}
