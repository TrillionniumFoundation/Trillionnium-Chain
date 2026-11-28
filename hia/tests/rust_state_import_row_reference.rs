use std::io::{self, Read, Write};

// Transport only. The test prepends exact original types and methods.
fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut rows = raw.as_slice();
    let mut out = Vec::new();
    while !rows.is_empty() {
        let (extent, after) = rows.split_at(4);
        let (frame, rest) = after.split_at(u32::from_le_bytes(extent.try_into().unwrap()) as usize);
        let (parts, trailer) = frame.split_at(frame.len() - 44);
        let width = |start| u32::from_le_bytes(trailer[start..start + 4].try_into().unwrap()) as usize;
        let (namespace, rem) = parts.split_at(width(0));
        let (key, value) = rem.split_at(width(4));
        if value.len() != width(8) {
            return Err(io::Error::other("differential fixtures require exact framing"));
        }
        let row = ExportRowV0 {
            namespace: namespace.to_vec(),
            key: key.to_vec(),
            value: value.to_vec(),
            row_digest: Digest32V0(trailer[12..].try_into().unwrap()),
        };
        let status = match row.validate() {
            Ok(()) => 0,
            Err(MigrationErrorV0::InvalidExportRow) => 101,
            Err(MigrationErrorV0::ForbiddenAuthorityState) => 104,
            Err(other) => return Err(io::Error::other(format!("unexpected original variant: {other:?}"))),
        };
        out.push(status);
        out.extend_from_slice(&ExportRowV0::canonical_digest(namespace, key, value).0);
        rows = rest;
    }
    io::stdout().write_all(&out)?;
    Ok(())
}
