use std::{cell::Cell, error::Error, io::{self, Read, Write}};

// Test-only context: accept no header except the exact locally built synthetic
// fixture passed to this observer. No cryptographic or transferable authority.
struct ExactLocalFixture {
    expected: FinalizedExportHeaderV0,
    called: Cell<u8>,
}

impl SourceFinalityVerifierV0 for ExactLocalFixture {
    type Error = io::Error;
    fn verify_finalized_export(&self, header: &FinalizedExportHeaderV0) -> Result<(), Self::Error> {
        if *header != self.expected || self.called.replace(1) != 0 {
            return Err(io::Error::other("different or duplicate local fixture"));
        }
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut requests = raw.chunks_exact(12);
    let mut out = Vec::new();
    for request in &mut requests {
        let word = |i| u32::from_le_bytes(request[i..i + 4].try_into().unwrap());
        let (count, seed, change_at) = (word(0), word(4), word(8));
        if count == 0 || count > 32724 || change_at > 32 {
            return Err(io::Error::other("unexpected local fixture bound"));
        }
        let rows: Vec<ExportRowV0> = (0..count).map(|i| {
            let namespace = b"local/ordered-row".to_vec();
            let key = i.to_be_bytes().to_vec();
            let value = [seed.to_be_bytes(), (i ^ seed).to_be_bytes()].concat();
            let row_digest = ExportRowV0::canonical_digest(&namespace, &key, &value);
            ExportRowV0 { namespace, key, value, row_digest }
        }).collect();
        let leaves: Vec<Digest32V0> = rows.iter().map(|row| row.row_digest).collect();
        let mut root = merkle_root_v0(&leaves);
        if change_at < 32 {
            root.0[change_at as usize] ^= 0x80;
        }
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: Digest32V0([1; 32]),
            source_protocol_digest: Digest32V0([2; 32]),
            source_height: 1,
            source_state_root: Digest32V0([3; 32]),
            source_schema_digest: Digest32V0([4; 32]),
            source_finality_proof_digest: Digest32V0([5; 32]),
            row_count: u64::from(count),
            export_root: root,
            header_digest: Digest32V0([0; 32]),
        };
        header.header_digest = header.canonical_digest();
        let context = ExactLocalFixture { expected: header, called: Cell::new(0) };
        let answer = verify_export_v0(&context, header, &rows);
        if context.called.get() != 1 {
            return Err(io::Error::other("fixture did not reach the original post-finality block exactly once"));
        }
        match answer {
            Ok(result) => {
                out.push(0);
                out.extend_from_slice(&result.ordered_rows_digest.0);
            }
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::ExportRootMismatch)) => {
                out.push(108);
                out.extend_from_slice(&[0; 32]);
            }
            _ => return Err(io::Error::other("unexpected original post-finality outcome")),
        }
        for leaf in leaves {
            out.extend_from_slice(&leaf.0);
        }
        out.extend_from_slice(&root.0);
    }
    if !requests.remainder().is_empty() {
        return Err(io::Error::other("incomplete request transport"));
    }
    io::stdout().write_all(&out)?;
    Ok(())
}
