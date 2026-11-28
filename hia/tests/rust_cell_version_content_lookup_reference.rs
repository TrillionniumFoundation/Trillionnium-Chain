//! Public unchanged Rust lookup of declared TCV2 metadata only.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellVersionContentV2};

fn main() -> io::Result<()> {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream)?;
    let mut cursor = stream.as_slice();
    let mut writer = io::BufWriter::new(io::stdout().lock());
    while !cursor.is_empty() {
        let count = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
        let (envelope, rest) = cursor[4..].split_at(count);
        cursor = rest;
        let (index, wire) = envelope.split_at(32);
        let selected = CellVersionContentV2::decode(wire);
        let found = selected
            .as_ref()
            .map_err(|error| match error {
                CellErrorV1::Invalid(reason) => *reason,
                _ => panic!("non-metadata error from pure decode"),
            })
            .and_then(|version| {
                version
                    .file(index.try_into().unwrap())
                    .map_err(|error| match error {
                        CellErrorV1::Invalid(reason) => reason,
                        _ => panic!("non-metadata error from pure lookup"),
                    })
            });
        match found {
            Ok(record) => {
                let chunks = record.chunks_sha512();
                let n = u32::try_from(chunks.len()).unwrap();
                writer.write_all(&[0])?;
                writer.write_all(&(100 + 64 * n).to_le_bytes())?;
                writer.write_all(&record.manifest())?;
                writer.write_all(&record.payload_sha512())?;
                writer.write_all(&n.to_be_bytes())?;
                for hash in chunks {
                    writer.write_all(hash)?;
                }
            }
            Err(reason) => {
                writer.write_all(&[1])?;
                writer.write_all(&(reason.len() as u32).to_le_bytes())?;
                writer.write_all(reason.as_bytes())?;
            }
        }
    }
    writer.flush()
}
