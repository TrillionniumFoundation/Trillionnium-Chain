// Linked only to the original source and actual pinned sha2 dependency.
fn main() -> io::Result<()> {
    let select_chunk = std::env::args().nth(1).as_deref() == Some("--chunk");
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut output = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        let (index, manifest) = if select_chunk {
            let index = u32::from_le_bytes(wire[..4].try_into().unwrap());
            (Some(index), &wire[4..])
        } else {
            (None, wire)
        };
        match manifest::CellManifestV1::decode(manifest) {
            Ok(value) => {
                if let Some(index) = index {
                    if let Some(row) = value.chunks().get(index as usize) {
                        output.write_all(&[0])?;
                        output.write_all(&value.id())?;
                        output.write_all(&index.to_le_bytes())?;
                        output.write_all(&row.size.to_le_bytes())?;
                        output.write_all(&row.sha256)?;
                    } else {
                        output.write_all(&[13])?;
                    }
                } else {
                    output.write_all(&[0])?;
                    output.write_all(&value.id())?;
                    output.write_all(&value.encode())?;
                }
            }
            Err(error) => {
                let code = match error {
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
                        _ => panic!("unexpected original diagnostic: {reason}"),
                    },
                    other => panic!("unexpected original error: {other:?}"),
                };
                output.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
