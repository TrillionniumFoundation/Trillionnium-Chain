//! Exact immutable commitment oracle; no store, funds, or custody operations.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellManifestV1, CellRetentionContractV1};

fn fixed<const N: usize>(data: &[u8], pos: usize) -> [u8; N] {
    data[pos..pos + N].try_into().unwrap()
}

fn manifest_status(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 2,
        CellErrorV1::Invalid(reason) => match reason {
            "manifest length" => 1,
            "manifest version" => 3,
            "family length" => 4,
            "family encoding" => 5,
            "chunk count" => 6,
            "manifest coverage" => 7,
            "model family" => 8,
            "chunk size" => 9,
            "cell size" => 10,
            "chunk coverage" => 11,
            "chunk length" => 12,
            _ => panic!("unexpected TCM1 error: {reason}"),
        },
        other => panic!("unexpected TCM1 error: {other:?}"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut raw = input.as_slice();
    while !raw.is_empty() {
        let len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        let (row, tail) = raw[4..].split_at(len);
        raw = tail;
        assert!(row.len() >= 129 && &row[..8] == b"NCRC0001");
        let successor = match row[128] {
            0 => None,
            1 => Some((fixed(row, 129), fixed(row, 161))),
            _ => panic!("private fixture is not a typed option"),
        };
        let manifest_at = if successor.is_some() { 193 } else { 129 };
        match CellManifestV1::decode(&row[manifest_at..]) {
            Ok(manifest) => {
                let id = manifest.id();
                let record = CellRetentionContractV1 {
                    operation: fixed(row, 40),
                    funding_operation: fixed(row, 72),
                    manifest,
                    retain_from_height: u64::from_be_bytes(fixed(row, 104)),
                    retain_until_height: u64::from_be_bytes(fixed(row, 112)),
                    maximum_repair_bytes: u64::from_be_bytes(fixed(row, 120)),
                    successor,
                };
                output.write_all(&[0])?;
                output.write_all(&id)?;
                output.write_all(&record.commitment(fixed(row, 8)))?;
            }
            Err(error) => {
                output.write_all(&[manifest_status(error)])?;
                output.write_all(&[0; 64])?;
            }
        }
    }
    Ok(())
}
