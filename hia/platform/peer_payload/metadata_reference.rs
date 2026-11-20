//! Observation transport for the actual original private payload primitives.
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use trnm_peer_lease::{
    qualification_payload_codec_v1, PayloadReplayNamespaceV1, PayloadReplayStoreV1,
};

fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).expect("fresh root"));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ns = PayloadReplayNamespaceV1::new([1; 32], 7, [3; 32], [4; 32], [5; 32]).unwrap();
    let mut owner = PayloadReplayStoreV1::open(root.join("metadata.wal"), ns).unwrap();
    let mut input = Vec::new();
    std::io::stdin()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut input)
        .unwrap();
    assert!(input.len() >= 8 && input.len() <= 512 * 1024 * 1024);
    let count = u64::from_le_bytes(input[..8].try_into().unwrap());
    let mut offset = 8;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for _ in 0..count {
        assert!(offset + 16 <= input.len());
        let op = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(
            input[offset + 8..offset + 16].try_into().unwrap(),
        ))
        .unwrap();
        offset += 16;
        let maximum = if op == 8 {
            64 * 1024 * 1024 + 136 + 380
        } else {
            512
        };
        assert!(len <= maximum && offset + len <= input.len());
        let (code, bytes) =
            qualification_payload_codec_v1(&mut owner, op, &input[offset..offset + len]);
        offset += len;
        output.extend_from_slice(&u64::from(code).to_le_bytes());
        output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(&bytes);
    }
    assert_eq!(offset, input.len());
    std::io::stdout().write_all(&output).unwrap();
}
