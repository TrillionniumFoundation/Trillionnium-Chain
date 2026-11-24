// Same original TCV1 sources and SHA-2 graph as the declared environment
// differential. This shell does not reimplement any original parse or check.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut out = io::stdout().lock();
    while !framed.is_empty() {
        let n = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, tail) = framed[4..].split_at(n);
        framed = tail;
        match CellVersionManifestV1::decode(wire) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                out.write_all(&[0])?;
                out.write_all(&value.environment().id())?;
                out.write_all(&(value.manifests().len() as u32).to_le_bytes())?;
                out.write_all(&value.commitment())?;
            }
            Err(CellErrorV1::Invalid(reason)) => {
                assert!(!reason.is_empty() && reason.len() <= 90);
                out.write_all(&[reason.len() as u8])?;
                out.write_all(reason.as_bytes())?;
            }
            Err(CellErrorV1::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                out.write_all(&[255])?;
            }
        }
    }
    Ok(())
}
