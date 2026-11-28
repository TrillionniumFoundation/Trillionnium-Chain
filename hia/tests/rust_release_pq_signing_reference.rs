// Actual V1 types, formatter and signature-set method are prepended unchanged
// by the Python harness. No signing key, signature authority or provider is used.
use std::io::Read;

fn take<const N: usize>(frame: &[u8], at: usize) -> [u8; N] {
    frame[at..at + N].try_into().unwrap()
}

fn boolean(value: u8) -> bool {
    match value {
        0 => false,
        1 => true,
        _ => panic!("original Rust bool cannot represent a malformed frame"),
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut frames = input.as_slice();
    let mut out = io::stdout().lock();
    while !frames.is_empty() {
        let len = u32::from_le_bytes(take(frames, 1)) as usize;
        let body = &frames[5..5 + len];
        match frames[0] {
            0 => {
                assert_eq!(len, 155);
                let role = match body[0] {
                    1 => PqReleaseRoleV1::NodeSoftware,
                    2 => PqReleaseRoleV1::ProtocolConfiguration,
                    3 => PqReleaseRoleV1::CellManifest,
                    4 => PqReleaseRoleV1::CellActivation,
                    _ => panic!("original enum cannot represent this role"),
                };
                let metadata = PqReleaseMetadataV1 {
                    network_id: take(body, 1),
                    role,
                    root_generation: u64::from_le_bytes(take(body, 33)),
                    role_version: u64::from_le_bytes(take(body, 41)),
                    expires_at: u64::from_le_bytes(take(body, 49)),
                    expected_checkpoint: take(body, 57),
                    previous_content: boolean(body[89]).then(|| take(body, 90)),
                    content: take(body, 122),
                    approved_content_rollback: boolean(body[154]),
                };
                let value = metadata.signing_message();
                assert_eq!(value.len(), 184);
                out.write_all(&[0])?;
                out.write_all(&value)?;
            }
            1 => {
                let count = usize::from(u16::from_le_bytes(take(body, 0)));
                assert_eq!(len, 2 + count * 4130);
                let signatures: Vec<_> = body[2..]
                    .chunks_exact(4130)
                    .map(|row| {
                        let width = usize::from(u16::from_le_bytes(take(row, 32)));
                        PqReleaseSignatureV1 {
                            key_id: take(row, 0),
                            signature: row[34..34 + width].to_vec(),
                        }
                    })
                    .collect();
                match pq_release_signature_digest_v1(&signatures) {
                    Ok(digest) => {
                        out.write_all(&[0])?;
                        out.write_all(&digest)?;
                    }
                    Err(PqReleaseErrorV1::InsufficientSignatures) => out.write_all(&[105])?,
                    Err(PqReleaseErrorV1::SignatureRejected) => out.write_all(&[106])?,
                    Err(PqReleaseErrorV1::DuplicateSigner) => out.write_all(&[107])?,
                    Err(other) => panic!("unexpected original signature-set result: {other:?}"),
                }
            }
            _ => unreachable!(),
        }
        frames = &frames[5 + len..];
    }
    Ok(())
}
