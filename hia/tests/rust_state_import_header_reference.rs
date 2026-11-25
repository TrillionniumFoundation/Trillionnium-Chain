use std::io::{self, Read, Write};

// Transport only. The test prepends the original structs and impls.
fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut rows = raw.chunks_exact(240);
    let mut out = Vec::new();
    for row in &mut rows {
        let digest = |start| Digest32V0(row[start..start + 32].try_into().unwrap());
        let integer = |start| u64::from_be_bytes(row[start..start + 8].try_into().unwrap());
        let header = FinalizedExportHeaderV0 {
            source_chain_id: digest(0),
            source_protocol_digest: digest(32),
            source_height: integer(64),
            source_state_root: digest(72),
            source_schema_digest: digest(104),
            source_finality_proof_digest: digest(136),
            row_count: integer(168),
            export_root: digest(176),
            header_digest: digest(208),
        };
        out.extend_from_slice(&header.canonical_digest().0);
    }
    if !rows.remainder().is_empty() {
        return Err(io::Error::other("incomplete header fixture"));
    }
    io::stdout().write_all(&out)?;
    Ok(())
}
