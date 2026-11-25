use std::{cell::Cell, error::Error, io::{self, Read, Write}};

struct OwnedFixture {
    exact: FinalizedExportHeaderV0,
    called: Cell<bool>,
}

impl SourceFinalityVerifierV0 for OwnedFixture {
    type Error = io::Error;
    fn verify_finalized_export(&self, header: &FinalizedExportHeaderV0) -> Result<(), Self::Error> {
        if *header != self.exact || self.called.replace(true) {
            return Err(io::Error::other("a different fixture cannot enter the local oracle"));
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
        let (size, rest) = input.split_at(4);
        let (batch, rest) = rest.split_at(u32::from_le_bytes(size.try_into().unwrap()) as usize);
        let root = Digest32V0(batch[..32].try_into().unwrap());
        let count = u32::from_le_bytes(batch[32..36].try_into().unwrap());
        let mut remaining = &batch[36..];
        let mut rows = Vec::new();
        for _ in 0..count {
            let (head, data) = remaining.split_at(44);
            let width = |i| u32::from_le_bytes(head[i..i+4].try_into().unwrap()) as usize;
            let (namespace, data) = data.split_at(width(0));
            let (key, data) = data.split_at(width(4));
            let (value, rest) = data.split_at(width(8));
            rows.push(ExportRowV0 {
                namespace: namespace.to_vec(), key: key.to_vec(), value: value.to_vec(),
                row_digest: Digest32V0(head[12..].try_into().unwrap()),
            });
            remaining = rest;
        }
        if !remaining.is_empty() {
            return Err(io::Error::other("original corpus is strictly framed"));
        }
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: Digest32V0([1;32]), source_protocol_digest: Digest32V0([2;32]),
            source_height: 1, source_state_root: Digest32V0([3;32]),
            source_schema_digest: Digest32V0([4;32]), source_finality_proof_digest: Digest32V0([5;32]),
            row_count: u64::from(count), export_root: root, header_digest: Digest32V0([0;32]),
        };
        header.header_digest = header.canonical_digest();
        let context = OwnedFixture { exact: header, called: Cell::new(false) };
        let observed = verify_export_v0(&context, header, &rows);
        if !context.called.get() {
            return Err(io::Error::other("fixture did not reach original post-finality semantics"));
        }
        let (code, ordered) = match observed {
            Ok(result) => (0, result.ordered_rows_digest.0),
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::InvalidExportRow)) => (101, [0;32]),
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::ForbiddenAuthorityState)) => (104, [0;32]),
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::ExportRootMismatch)) => (108, [0;32]),
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::RowsNotStrictlyOrdered)) => (109, [0;32]),
            _ => return Err(io::Error::other("unrelated original downstream error")),
        };
        output.push(code);
        output.extend_from_slice(&ordered);
        input = rest;
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
