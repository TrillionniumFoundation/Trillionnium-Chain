// Exact original context codec precedes this isolated fixture transport.
fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut raw = &input[..];
    let mut out = io::stdout().lock();
    while !raw.is_empty() {
        let mode = raw[0];
        let n = u16::from_le_bytes(raw[1..3].try_into().unwrap()) as usize;
        let (body, rest) = raw[3..].split_at(n);
        raw = rest;
        let result = match mode {
            0 => IntegerLinearContextV1::new(
                body[..32].try_into().unwrap(),
                body[32..64].try_into().unwrap(),
                body[64],
            ),
            1 => IntegerLinearContextV1::decode(body),
            _ => panic!("fixture mode"),
        };
        match result {
            Ok(value) => {
                out.write_all(&[0])?;
                out.write_all(&value.family())?;
                out.write_all(&value.parent_artifact())?;
                out.write_all(&[value.slot()])?;
                out.write_all(&value.contract_id())?;
                out.write_all(&value.canonical_bytes())?;
            }
            Err(error) => {
                let code = match error {
                    IntegerLinearErrorV1::Length => 1,
                    IntegerLinearErrorV1::CanonicalEncoding => 2,
                    IntegerLinearErrorV1::Family => 3,
                    IntegerLinearErrorV1::Slot => 4,
                    _ => panic!("not a fixed context outcome: {error}"),
                };
                out.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
