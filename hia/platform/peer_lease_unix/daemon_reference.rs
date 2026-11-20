//! Observe the unchanged public Rust Unix daemon API.
use std::{ffi::OsString, io::{self, Read, Write}, os::unix::ffi::OsStringExt, path::PathBuf, time::Duration};
use trnm_peer_lease::{PeerLeaseErrorV1, UnixPeerLeaseDaemonV1};
fn word(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at+8].try_into().unwrap()) }
fn error(e: PeerLeaseErrorV1) -> (u64, u64) {
    match e {
        PeerLeaseErrorV1::Rejected(code) => (4, code as u64),
        PeerLeaseErrorV1::InvalidRequest(message) => (1, match message {
            "journal path must be absolute" => 1, "journal parent" => 2, "journal anchor filename" => 3,
            "journal parent must be a directory" => 4, "journal parent must have private mode 0700" => 5,
            "journal parent must be owned by the effective user" => 6, "journal parent must not be a symlink alias" => 7,
            "journal parent ancestry must not be group/world writable" => 8,
            "journal parent ancestry must be root- or owner-controlled" => 9,
            "invalid lease identity" => 10, "lease generation must be positive" => 11,
            "lease TTL is outside the bounded profile" => 12, "lease TTL overflow" => 13,
            "journal parent must be a real directory" => 14, "journal parent has no existing ancestor" => 15,
            "journal authority file must be a private regular file" => 16,
            "journal anchor descriptor/path identity changed" => 17,
            "peer-lease socket path is not a narrow absolute path" => 1002,
            "peer-lease socket path exceeds Unix sun_path limit" => 1003,
            "peer-lease socket parent is not canonical" => 1013,
            "peer-lease path is not a private Unix socket" => 1014,
            "invalid lease direction" => 1015, "invalid lease scope" => 1016,
            "peer-lease daemon timeout must be positive" => 1001,
            "peer-lease journal path is not a narrow absolute path" => 1004,
            "peer-lease journal path requires a UTF-8 filename" => 1005,
            "peer-lease socket/journal paths collide" => 1006,
            "peer-lease socket path already exists" => 1007,
            "bound peer-lease path is not a Unix socket" => 1008,
            "peer-lease socket cleanup guard is not armed" => 1009,
            "peer-lease socket identity or permissions changed" => 1010,
            "system clock predates Unix epoch" => 1011,
            "system clock overflow" => 1012,
            other => panic!("unmapped original InvalidRequest: {other}"),
        }),
        PeerLeaseErrorV1::Protocol(message) => (3, match message {
            "invalid peer-lease frame" => 1, "peer-lease frame length mismatch" => 2,
            "truncated peer-lease frame" => 3, "unsupported peer-lease schema" => 4,
            "unknown lease operation" => 5, "trailing peer-lease frame bytes" => 6,
            "unsupported peer-lease response schema" => 9, "unknown peer-lease response kind" => 10,
            "invalid peer-lease token" => 13, "unknown lease rejection code" => 14,
            "invalid peer-lease frame magic" => 20, "peer-lease frame exceeds limit" => 21,
            other => panic!("unmapped original Protocol: {other}"),
        }),
        PeerLeaseErrorV1::Io(e) => (2, if let Some(errno) = e.raw_os_error() { errno as u64 } else {
            match (e.kind(), e.to_string().as_str()) {
                (io::ErrorKind::TimedOut, "peer-lease operation deadline exceeded") => 4098,
                (io::ErrorKind::UnexpectedEof, "peer-lease stream closed before frame completed") => 4099,
                (io::ErrorKind::WriteZero, "peer-lease stream accepted no frame bytes") => 4100,
                (io::ErrorKind::InvalidInput, "invalid peer-lease descriptor") => 4101,
                (io::ErrorKind::InvalidInput, message) if message.starts_with("invalid lease daemon poll timeout: ") => 4103,
                _ => panic!("unmapped original I/O: {e:?}"),
            }
        }),
    }
}
fn main() {
    let mut bytes = Vec::new(); io::stdin().read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() >= 56 && &bytes[..8] == b"PLUN0001");
    assert_eq!(word(&bytes, 8), 1);
    let sn = usize::try_from(word(&bytes,16)).unwrap();
    let jn = usize::try_from(word(&bytes,24)).unwrap();
    assert_eq!(word(&bytes,32), 0);
    assert_eq!(bytes.len(), 56 + sn + jn);
    let ns = word(&bytes,48); assert!(ns < 1_000_000_000);
    let socket = PathBuf::from(OsString::from_vec(bytes[56..56+sn].to_vec()));
    let journal = PathBuf::from(OsString::from_vec(bytes[56+sn..].to_vec()));
    let daemon = UnixPeerLeaseDaemonV1::new(socket, journal).with_timeout(Duration::new(word(&bytes,40),ns as u32));
    let (category, code) = match daemon.run() { Ok(()) => (0u64,0u64), Err(e) => error(e) };
    let mut out=b"PLUR0001".to_vec();out.extend_from_slice(&category.to_le_bytes());out.extend_from_slice(&code.to_le_bytes());
    io::stdout().write_all(&out).unwrap();
}
