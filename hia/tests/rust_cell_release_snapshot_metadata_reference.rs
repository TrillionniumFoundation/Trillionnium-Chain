// Synthetic qualification only. The internally computed fixture digest is
// solely to enter the original post-pin decoder path, never an owner pin.
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let mut framed = bytes.as_slice();
    let mut out = io::stdout().lock();
    while !framed.is_empty() {
        let n = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        let (wire, tail) = framed[4..].split_at(n);
        framed = tail;
        let synthetic = wire_commitment(wire);
        assert_ne!(synthetic, [0; 64]);
        match CellReleaseSnapshotV1::decode_pinned(wire, synthetic) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                assert_eq!(value.commitment(), synthetic);
                out.write_all(&[0])?;
                out.write_all(&value.composition_file().to_be_bytes())?;
                out.write_all(&value.composition_profile())?;
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
