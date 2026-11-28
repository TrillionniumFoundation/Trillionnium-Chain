//! Unchanged public TCV3 decoder and selected-root commitment getter.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellVersionContentClosureV3};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut cursor = input.as_slice();
    let mut writer = io::BufWriter::new(io::stdout().lock());
    while !cursor.is_empty() {
        let length = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
        let (wire, rest) = cursor[4..].split_at(length);
        cursor = rest;
        match CellVersionContentClosureV3::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                let root_commitments = value.root_commitments();
                assert_eq!(root_commitments.len(), value.roots().len());
                writer.write_all(&[0])?;
                writer.write_all(&(root_commitments.len() as u32).to_le_bytes())?;
                for commitment in root_commitments {
                    writer.write_all(&commitment)?;
                }
            }
            Err(CellErrorV1::Invalid(reason)) => {
                writer.write_all(&[u8::try_from(reason.len()).unwrap()])?;
                writer.write_all(reason.as_bytes())?;
            }
            Err(_) => panic!("metadata-only original returned a different error type"),
        }
    }
    writer.flush()
}
