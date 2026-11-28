// Observer for the unchanged original TMA1 methods and exact pure dependencies.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut out = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        match tensor_contract::CellTensorModelManifestV1::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                out.write_all(&[0])?;
                out.write_all(&value.id())?;
                out.write_all(&value.root().id())?;
                out.write_all(&value.contract().id())?;
            }
            Err(error) => out.write_all(&[tensor_model_error(error)])?,
        }
    }
    Ok(())
}

fn tensor_model_error(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 2,
        CellErrorV1::Invalid(reason) => match reason {
            "tensor model manifest length" => 90,
            "tensor model manifest version" => 91,
            "tensor model section length" => 92,
            "tensor model manifest suffix" => 93,
            "tensor closure file index" => 94,
            "tensor closure payload size" => 95,
            "tensor missing required file" => 96,
            "tensor model canonical encoding" => 97,
            contract if contract.starts_with("tensor ") => {
                64 + contract_observer::diag(CellErrorV1::Invalid(reason))
            }
            _ => root_observer::diag(CellErrorV1::Invalid(reason)),
        },
        other => panic!("unexpected original TMA1 diagnostic {other:?}"),
    }
}
