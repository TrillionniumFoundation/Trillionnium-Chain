// The Python fixture prefixes the original V0 code and independent SHA-256
// seam. This target exercises only the original pure provenance scope.
use std::io::Read;

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut feed = raw.as_slice();
    let mut out = io::stdout().lock();
    while !feed.is_empty() {
        let mode = feed[0];
        let count = usize::from(u16::from_le_bytes(feed[1..3].try_into().unwrap()));
        let end = 259 + 578 * count;
        let field = |at| Digest32V0(feed[at..at + 32].try_into().unwrap());
        let mut value = bundle(20, 7).provenance;
        value.builder_identity_digest = field(3);
        value.workflow_digest = field(35);
        value.run_identity_digest = field(67);
        value.isolated_environment_digest = field(99);
        value.exact_source_digest = field(131);
        value.artifact_set_digest = field(163);
        value.sbom_digest = field(195);
        value.provenance_digest = field(227);
        value.build_inputs = feed[259..end]
            .chunks_exact(578)
            .map(|slot| {
                let width = usize::from(u16::from_le_bytes(slot[..2].try_into().unwrap()));
                BuildInputV0 {
                    logical_name: slot[66..66 + width].to_vec(),
                    source_digest: Digest32V0(slot[2..34].try_into().unwrap()),
                    content_digest: Digest32V0(slot[34..66].try_into().unwrap()),
                }
            })
            .collect();
        let code = match mode {
            0 => 0,
            1 => match value.validate() {
                Ok(()) => 0,
                Err(ReleaseBundleErrorV0::InvalidProvenance) => 105,
                Err(ReleaseBundleErrorV0::InvalidBuildInput) => 106,
                Err(ReleaseBundleErrorV0::DuplicateBuildInput) => 107,
                Err(other) => panic!("unexpected original result: {other:?}"),
            },
            _ => unreachable!(),
        };
        out.write_all(&[code])?;
        // Separate arithmetic observation, even when candidate validation failed.
        // That extra test computation is not a candidate acceptance result.
        out.write_all(&value.canonical_digest().0)?;
        let mut inputs = value.build_inputs;
        inputs.sort_unstable();
        for row in inputs {
            out.write_all(&row.canonical_digest().0)?;
        }
        feed = &feed[end..];
    }
    Ok(())
}
