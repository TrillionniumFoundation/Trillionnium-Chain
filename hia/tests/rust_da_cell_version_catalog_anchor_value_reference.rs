//! Original immutable CVA3 decode, encode and getters; no catalog access.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellVersionCatalogAnchorV3};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    let mut rows = input.as_slice();
    while !rows.is_empty() {
        let len = u32::from_le_bytes(rows[..4].try_into().unwrap()) as usize;
        let (row, rest) = rows[4..].split_at(len);
        rows = rest;
        match CellVersionCatalogAnchorV3::decode(row) {
            Ok(anchor) => {
                let canonical = anchor.encode();
                assert_eq!(canonical, row);
                output.write_all(&[0])?;
                output.write_all(&anchor.generation().to_le_bytes())?;
                output.write_all(&anchor.commitment())?;
                output.write_all(&canonical)?;
            }
            Err(CellErrorV1::Invalid(reason)) => {
                let status = match reason {
                    "version retention truncated contract" => 20,
                    "version retention anchor namespace" => 21,
                    "version retention anchor encoding" => 22,
                    _ => panic!("unexpected original CVA3 rejection: {reason}"),
                };
                output.write_all(&[status])?;
                output.write_all(&[0; 84])?;
            }
            Err(other) => panic!("unexpected CVA3 error: {other:?}"),
        }
    }
    Ok(())
}
