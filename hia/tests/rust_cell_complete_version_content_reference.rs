//! Offline comparison against the unchanged public DA model-content codec.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellVersionContentV2};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut cursor = input.as_slice();
    let mut writer = io::BufWriter::new(io::stdout().lock());
    while !cursor.is_empty() {
        let length = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
        let (wire, rest) = cursor[4..].split_at(length);
        cursor = rest;
        match CellVersionContentV2::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                writer.write_all(&[0])?;
                writer.write_all(&(value.contents().len() as u32).to_le_bytes())?;
                writer.write_all(&value.commitment())?;
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
