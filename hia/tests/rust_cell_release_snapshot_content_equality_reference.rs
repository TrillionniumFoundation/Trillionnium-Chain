// Offline explicit synthetic digest observation. Do not calculate or replace
// the caller-supplied bytes before invoking the actual original decoder.
fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut frames = input.as_slice();
    let mut out = io::stdout().lock();
    while !frames.is_empty() {
        let size = u32::from_le_bytes(frames[..4].try_into().unwrap()) as usize;
        let (packet, rest) = frames[4..].split_at(size);
        frames = rest;
        let expected: [u8; 64] = packet[..64].try_into().unwrap();
        let wire = &packet[64..];
        match CellReleaseSnapshotV1::decode_pinned(wire, expected) {
            Ok(value) => {
                assert_eq!(value.encode(), wire);
                assert_eq!(value.commitment(), expected);
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
