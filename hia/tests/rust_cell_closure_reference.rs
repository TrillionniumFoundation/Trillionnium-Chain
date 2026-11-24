// Test framing only: exact closure.rs, manifest.rs and locked sha2 do all work.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut output = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        observe_cell_dependency_closure(wire, &mut output)?;
    }
    Ok(())
}

fn observe_cell_dependency_closure(wire: &[u8], output: &mut impl Write) -> io::Result<()> {
    match closure::CellReleaseClosureV1::decode(wire) {
        Ok(value) => {
            assert_eq!(value.encode(), wire);
            output.write_all(&[0])?;
            output.write_all(&value.id())?;
            output.write_all(&value.release().id())?;
            output.write_all(&(value.files().len() as u32).to_le_bytes())?;
            output.write_all(&(value.release().cells().len() as u32).to_le_bytes())
        }
        Err(error) => {
            let status = match error {
                CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 2,
                CellErrorV1::Invalid(reason) => match reason {
                    "closure wire length" => 1,
                    "closure version" => 3,
                    "closure release length" => 4,
                    "closure index count" => 5,
                    "closure file count" => 6,
                    "closure path length" => 7,
                    "closure path encoding" => 8,
                    "closure role" => 9,
                    "closure trailing bytes" => 10,
                    "closure generation" => 11,
                    "closure loader profile" => 12,
                    "closure roots" => 13,
                    "closure canonical paths" => 14,
                    "closure case-fold path alias" => 15,
                    "closure portable path" => 16,
                    "closure path depth" => 17,
                    "closure path component" => 18,
                    "closure reserved path" => 19,
                    "closure file/directory alias" => 20,
                    "closure payload identity" => 21,
                    "closure manifest alias" => 22,
                    "closure dependency" => 23,
                    "closure self dependency" => 24,
                    "closure release membership" => 25,
                    "closure graph depth" => 26,
                    "closure dependency cycle" => 27,
                    "closure unreachable file" => 28,
                    "release manifest length" => 33,
                    "release version" => 34,
                    "release family length" => 36,
                    "release family encoding" => 37,
                    "model family" => 38,
                    "release context digest" => 39,
                    "release cell count" => 40,
                    "release manifest coverage" => 41,
                    "release cell order/duplicates" => 42,
                    "release cell digest" => 43,
                    other => panic!("unexpected original closure diagnostic {other}"),
                },
                other => panic!("unexpected original closure diagnostic {other:?}"),
            };
            output.write_all(&[status])
        }
    }
}
