use std::{cell::Cell, error::Error, io::{self, Read, Write}};

struct RefusingObserver(Cell<u8>);

impl SourceFinalityVerifierV0 for RefusingObserver {
    type Error = io::Error;
    fn verify_finalized_export(&self, _: &FinalizedExportHeaderV0) -> Result<(), Self::Error> {
        self.0.set(self.0.get() + 1);
        Err(io::Error::other("the differential sentinel always refuses"))
    }
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut rows = raw.chunks_exact(248);
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
        let actual = integer(240);
        if actual > 1024 {
            return Err(io::Error::other("actual Rust fixture row count too large"));
        }
        // Deliberately invalid rows ensure the admission stage never observes
        // them before the independent finality verifier has accepted.
        let invalid = ExportRowV0 { namespace: vec![], key: vec![], value: vec![],
                                    row_digest: Digest32V0([0; 32]) };
        let observed = vec![invalid; actual as usize];
        let verifier = RefusingObserver(Cell::new(0));
        let result = verify_export_v0(&verifier, header, &observed);
        let status = match result {
            Err(MigrationHostErrorV0::Protocol(MigrationErrorV0::InvalidExportHeader)) => 107,
            Err(MigrationHostErrorV0::SourceFinality(err))
                if err.to_string() == "the differential sentinel always refuses" => 0,
            _ => return Err(io::Error::other("original verify_export_v0 crossed the sentinel fence")),
        };
        out.extend_from_slice(&[status, verifier.0.get()]);
    }
    if !rows.remainder().is_empty() {
        return Err(io::Error::other("incomplete header-admission transport frame"));
    }
    io::stdout().write_all(&out)?;
    Ok(())
}
