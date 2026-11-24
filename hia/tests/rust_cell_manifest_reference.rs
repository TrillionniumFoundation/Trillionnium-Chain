// Linked only to the original source and actual pinned sha2 dependency.
fn main() -> io::Result<()> {
    let mode = std::env::args().nth(1);
    let select_chunk = mode.as_deref() == Some("--chunk");
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut output = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        if mode.as_deref() == Some("--release") {
            match manifest::CellReleaseManifestV1::decode(wire) {
                Ok(value) => {
                    assert_eq!(value.encode(), wire);
                    output.write_all(&[0])?;
                    output.write_all(&value.id())?;
                    output.write_all(&(value.cells().len() as u32).to_le_bytes())?;
                }
                Err(error) => output.write_all(&[release_error_status(error)])?,
            }
            continue;
        }
        if mode.as_deref() == Some("--binding") {
            match binding::observe(wire) {
                Ok(row) => {
                    output.write_all(&[0])?;
                    output.write_all(&row)?;
                }
                Err(error) => output.write_all(&[error_status(error)])?,
            }
            continue;
        }
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
            Err(error) => output.write_all(&[error_status(error)])?,
        }
    }
    Ok(())
}

fn error_status(error: CellErrorV1) -> u8 {
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
            "RS46 chunk index" => 13,
            "RS46 context pin" => 14,
            "RS46 manifest pin" => 15,
            _ => panic!("unexpected original diagnostic: {reason}"),
        },
        other => panic!("unexpected original error: {other:?}"),
    }
}

fn release_error_status(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 3,
        CellErrorV1::Invalid(reason) => match reason {
            "release manifest length" => 1,
            "release version" => 2,
            "release family length" => 4,
            "release family encoding" => 5,
            "model family" => 6,
            "release context digest" => 7,
            "release cell count" => 8,
            "release manifest coverage" => 9,
            "release cell order/duplicates" => 10,
            "release cell digest" => 11,
            _ => panic!("unexpected original release diagnostic: {reason}"),
        },
        other => panic!("unexpected original release error: {other:?}"),
    }
}
