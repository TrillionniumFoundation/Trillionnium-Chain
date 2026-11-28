//! Immutable TCX1 public original decode, encode and identity; no CAS calls.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellChunkDeltaV1, CellErrorV1};

fn status(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 2,
        CellErrorV1::Invalid(reason) => match reason {
            "delta length" => 20,
            "delta version" => 21,
            "delta base" => 22,
            "delta target length" => 23,
            "delta source length" => 24,
            "delta source index" => 25,
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
    let mut rows = input.as_slice();
    while !rows.is_empty() {
        let len = u32::from_le_bytes(rows[..4].try_into().unwrap()) as usize;
        let (row, tail) = rows[4..].split_at(len);
        rows = tail;
        match CellChunkDeltaV1::decode(row) {
            Ok(delta) => {
                assert_eq!(delta.encode(), row);
                output.write_all(&[0])?;
                output.write_all(&delta.id())?;
            }
            Err(error) => {
                output.write_all(&[status(error)])?;
                output.write_all(&[0; 32])?;
            }
        }
    }
    Ok(())
}
