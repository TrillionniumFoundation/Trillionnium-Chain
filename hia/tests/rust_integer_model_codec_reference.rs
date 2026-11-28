// The original IntegerModelV2, PON hash framing and scalar constants are prefixed.
fn main() -> io::Result<()> {
    let mut wire = Vec::new();
    io::stdin().read_to_end(&mut wire)?;
    let mut rest = wire.as_slice();
    let mut output = io::stdout().lock();
    while !rest.is_empty() {
        let length = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        let (next, tail) = rest[4..].split_at(length);
        rest = tail;
        let version = next[0];
        let mode = next[1];
        let active = next[2];
        let family: Hash = next[4..36].try_into().unwrap();
        let content = &next[36..];
        let decoded = match (version, mode) {
            (2 | 3, 0) => {
                assert_eq!(content.len() % 2, 0);
                let values = content
                    .chunks_exact(2)
                    .map(|c| i16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if version == 2 {
                    IntegerModelV2::from_coefficients(family, values)
                } else {
                    IntegerModelV2::from_evolution_coefficients(family, values, active)
                }
            }
            (2, 1) => IntegerModelV2::decode(content, family),
            (3, 1) => IntegerModelV2::decode_evolution(content, family),
            _ => panic!("invalid typed test mode"),
        };
        match decoded {
            Ok(model) => {
                output.write_all(&[0])?;
                output.write_all(&model.id())?;
                output.write_all(&model.encode())?;
            }
            Err(error) => {
                let code = match error {
                    "FACTOR_MODEL_LENGTH" => 1,
                    "FACTOR_MODEL_VERSION" => 2,
                    "FACTOR_MODEL_CONTEXT" => 3,
                    "EVOLUTION_GRAPH" => 4,
                    "FACTOR_MODEL_RANGE" => 5,
                    "FACTOR_MODEL_CANONICAL" => 6,
                    _ => panic!("unexpected codec error: {error}"),
                };
                output.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
