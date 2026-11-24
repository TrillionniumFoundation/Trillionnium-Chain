// Observer for exact unchanged declarations/methods from original tensor.rs.
// No safetensors header, reader, payload, serde or pin path is compiled here.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut out = io::stdout().lock();
    while !framed.is_empty() {
        let extent = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, rest) = framed[4..].split_at(extent);
        framed = rest;
        match tensor_contract::CellTensorContractV1::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                out.write_all(&[0])?;
                out.write_all(&value.id())?;
                out.write_all(&(value.files().len() as u32).to_le_bytes())?;
                let rows: usize = value.files().iter().map(|file| file.tensors.len()).sum();
                out.write_all(&(rows as u32).to_le_bytes())?;
            }
            Err(error) => out.write_all(&[contract_error(error)])?,
        }
    }
    Ok(())
}

fn contract_error(error: CellErrorV1) -> u8 {
    match error {
        CellErrorV1::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => 6,
        CellErrorV1::Invalid(reason) => match reason {
            "tensor contract length" => 1,
            "tensor contract version" => 2,
            "tensor hash profile" => 3,
            "tensor codec" => 4,
            "tensor file count" => 5,
            "tensor count" => 7,
            "tensor truncated roster" => 8,
            "tensor name length" => 9,
            "tensor name encoding" => 10,
            "tensor dtype" => 11,
            "tensor rank" => 12,
            "tensor contract suffix" => 13,
            "tensor contract canonical encoding" => 14,
            "tensor model root" => 15,
            "tensor canonical files" => 16,
            "tensor file roster" => 17,
            "tensor canonical names" => 18,
            "tensor name" => 19,
            "tensor dimension" => 20,
            "tensor shape overflow" => 21,
            "tensor byte bound" => 22,
            "tensor file bytes" => 23,
            other => panic!("unexpected original tensor contract diagnostic {other}"),
        },
        other => panic!("unexpected original tensor contract diagnostic {other:?}"),
    }
}
