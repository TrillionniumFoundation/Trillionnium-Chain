use std::{cell::Cell, error::Error, io::{self, Read, Write}};

struct OwnedFixture {
    exact: FinalizedExportHeaderV0,
    calls: Cell<u8>,
}

impl SourceFinalityVerifierV0 for OwnedFixture {
    type Error = io::Error;
    fn verify_finalized_export(&self, header: &FinalizedExportHeaderV0) -> Result<(), Self::Error> {
        if *header != self.exact || self.calls.replace(1) != 0 {
            return Err(io::Error::other("wrong local test fixture"));
        }
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = raw.as_slice();
    let mut output = Vec::new();
    while !input.is_empty() {
        let (size, next) = input.split_at(4);
        let (frame, rest) = next.split_at(u32::from_le_bytes(size.try_into().unwrap()) as usize);
        let (body, trailer) = frame.split_at(frame.len() - 52);
        let length = |i| u32::from_le_bytes(trailer[i..i + 4].try_into().unwrap()) as usize;
        let (ns, body) = body.split_at(length(0));
        let (key, body) = body.split_at(length(4));
        let (value, body) = body.split_at(length(8));
        let (old_ns, old_key) = body.split_at(length(12));
        if old_key.len() != length(16) {
            return Err(io::Error::other("incomplete valid fixture body"));
        }
        let mut rows = Vec::with_capacity(2);
        if !old_ns.is_empty() {
            let prior = ExportRowV0 {
                namespace: old_ns.to_vec(), key: old_key.to_vec(), value: vec![],
                row_digest: ExportRowV0::canonical_digest(old_ns, old_key, &[]),
            };
            // The held tuple is from an actual previously admissible row.
            prior.validate().map_err(|e| io::Error::other(format!("invalid prior: {e:?}")))?;
            rows.push(prior);
        }
        rows.push(ExportRowV0 { namespace: ns.to_vec(), key: key.to_vec(), value: value.to_vec(),
                                row_digest: Digest32V0(trailer[20..].try_into().unwrap()) });
        let leaves: Vec<Digest32V0> = rows.iter().map(|r| r.row_digest).collect();
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: Digest32V0([1;32]), source_protocol_digest: Digest32V0([2;32]),
            source_height: 1, source_state_root: Digest32V0([3;32]),
            source_schema_digest: Digest32V0([4;32]), source_finality_proof_digest: Digest32V0([5;32]),
            row_count: rows.len() as u64, export_root: merkle_root_v0(&leaves),
            header_digest: Digest32V0([0;32]),
        };
        header.header_digest = header.canonical_digest();
        let fixture = OwnedFixture { exact: header, calls: Cell::new(0) };
        let result = verify_export_v0(&fixture, header, &rows);
        if fixture.calls.get() != 1 {
            return Err(io::Error::other("fixture did not reach the post-finality stage"));
        }
        let status = match result {
            Ok(_) => 0,
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::InvalidExportRow)) => 101,
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::ForbiddenAuthorityState)) => 104,
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::RowsNotStrictlyOrdered)) => 109,
            _ => return Err(io::Error::other("unexpected original ordered-row outcome")),
        };
        output.push(status);
        input = rest;
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
