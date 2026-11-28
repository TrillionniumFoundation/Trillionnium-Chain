//! Locked public builder-provenance canonical digest only.
use std::io::{self, Read, Write};
use trnm_release_bundle::{BuildInputV0, BuilderProvenanceV0, Digest32V0};

fn short(r:&[u8],p:usize)->usize {
    usize::from(u16::from_le_bytes(r[p..p+2].try_into().unwrap()))
}
fn digest(r:&[u8],p:usize)->Digest32V0 {
    Digest32V0(r[p..p+32].try_into().unwrap())
}
fn main()->io::Result<()> {
    let mut raw=Vec::new(); io::stdin().read_to_end(&mut raw)?;
    let mut rows=raw.as_slice(); let mut out=io::stdout().lock();
    while !rows.is_empty() {
        assert_eq!(rows[0],0);
        let stop=259+578*short(rows,1);
        let inputs=rows[259..stop].chunks_exact(578).map(|r| BuildInputV0 {
            logical_name:r[66..66+short(r,0)].to_vec(),
            source_digest:digest(r,2),
            content_digest:digest(r,34),
        }).collect();
        let p=BuilderProvenanceV0 {
            builder_identity_digest:digest(rows,3), workflow_digest:digest(rows,35),
            run_identity_digest:digest(rows,67), isolated_environment_digest:digest(rows,99),
            exact_source_digest:digest(rows,131), artifact_set_digest:digest(rows,163),
            sbom_digest:digest(rows,195), provenance_digest:digest(rows,227),
            build_inputs:inputs,
        };
        out.write_all(&p.canonical_digest().0)?;
        rows=&rows[stop..];
    }
    Ok(())
}
