// Private framing only. The complete original Rust source owns both hashes.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut out = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        match model_root::CellModelReleaseRootV1::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                out.write_all(&[0])?;
                out.write_all(&value.id())?;
                out.write_all(&value.router_commitment())?;
                out.write_all(&(value.lineage().len() as u32).to_le_bytes())?;
            }
            Err(error) => out.write_all(&[model_root_status(error)])?,
        }
    }
    Ok(())
}

fn model_root_status(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Invalid(reason) => match reason {
            "model root length" => 50,
            "model root version" => 52,
            "model root closure length" => 53,
            "model root lineage length" => 54,
            "model root canonical lineage" => 55,
            "model root router roster" => 56,
            "model root canonical encoding" => 57,
            other => closure_observer::closure_error_status(CellErrorV1::Invalid(other)),
        },
        other => closure_observer::closure_error_status(other),
    }
}
