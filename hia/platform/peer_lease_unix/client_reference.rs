//! Test observer for the unchanged public Rust Unix client API.
use std::{ffi::OsString, io::{self, Read, Write}, os::unix::ffi::OsStringExt, path::PathBuf, time::{Duration, Instant}};
use trnm_peer_lease::{ExternalPeerLeaseAuthorityV1, PeerLeaseDirectionV1, PeerLeaseErrorV1, PeerLeaseScopeV1, PeerLeaseTokenV1, UnixPeerLeaseClientV1};

fn word(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }
fn bytes32(b: &[u8], at: usize) -> [u8; 32] { b[at..at + 32].try_into().unwrap() }
fn token_bytes(t: PeerLeaseTokenV1) -> Vec<u8> {
    let s = t.scope(); let mut out = Vec::new();
    out.extend_from_slice(&s.local_id()); out.extend_from_slice(&s.remote_id());
    out.push(match s.direction() { PeerLeaseDirectionV1::Outbound => 1, PeerLeaseDirectionV1::Inbound => 2 });
    out.extend_from_slice(&s.epoch().to_le_bytes()); out.extend_from_slice(&s.peer_scope_id());
    out.extend_from_slice(&t.session_id()); out.extend_from_slice(&t.generation().to_le_bytes());
    out.extend_from_slice(&t.expires_at_ms().to_le_bytes()); out.extend_from_slice(&t.record_hash()); out
}
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
                _ => panic!("unmapped original I/O: {e:?}"),
            }
        }),
    }
}
fn absolute_deadline(sec: u64, nanos: u64) -> Instant {
    // This test-only conversion samples the same OS monotonic clock. It does
    // not replace any original transport, validation, or deadline function.
    let now = Instant::now();
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) }, 0);
    let actual = Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
    let requested = Duration::new(sec, nanos as u32);
    if requested >= actual { now.checked_add(requested - actual).unwrap_or(now) }
    else { now.checked_sub(actual - requested).unwrap_or(now) }
}
fn execute(b: &[u8]) -> Result<Vec<u8>, (u64, u64)> {
    let malformed = (100, 100);
    if b.len() < 80 || &b[..8] != b"PLUC0001" { return Err(malformed); }
    let op = word(b, 8); let path_len = usize::try_from(word(b, 16)).map_err(|_| malformed)?;
    let timeout_s = word(b, 24); let timeout_n = word(b, 32); let has_deadline = word(b, 40);
    let deadline_s = word(b, 48); let deadline_n = word(b, 56); let request_len = word(b, 64);
    if !(1..=3).contains(&op) || timeout_n >= 1_000_000_000 || deadline_n >= 1_000_000_000
        || has_deadline > 1 || word(b, 72) != 0 || request_len != if op == 3 { 201 } else { 0 }
        || 80usize.checked_add(path_len).and_then(|n| n.checked_add(request_len as usize)) != Some(b.len()) {
        return Err(malformed);
    }
    let path = PathBuf::from(OsString::from_vec(b[80..80 + path_len].to_vec()));
    let mut client = UnixPeerLeaseClientV1::connect(path).with_timeout(Duration::new(timeout_s, timeout_n as u32));
    if has_deadline == 1 { client = client.with_deadline(absolute_deadline(deadline_s, deadline_n)); }
    if op == 1 { return client.preflight().map(|()| Vec::new()).map_err(error); }
    if op == 2 { return client.binding_digest_v1().map(|d| d.to_vec()).map_err(error); }
    let r = &b[80 + path_len..]; let method = word(r, 0);
    let direction = match r[72] { 1 => PeerLeaseDirectionV1::Outbound, 2 => PeerLeaseDirectionV1::Inbound, _ => return Err(malformed) };
    let scope = PeerLeaseScopeV1::new(bytes32(r, 8), bytes32(r, 40), direction, word(r, 73), bytes32(r, 81)).map_err(|_| malformed)?;
    let session = bytes32(r, 113); let generation = word(r, 145); let expires = word(r, 153);
    let ttl = word(r, 161); let hash = bytes32(r, 169);
    match method {
        1 => client.acquire(scope, session, generation, ttl).map(token_bytes).map_err(error),
        2..=4 => {
            let token = PeerLeaseTokenV1::from_parts(scope, session, generation, expires, hash).map_err(|_| malformed)?;
            match method {
                2 => client.renew(token, ttl).map(token_bytes).map_err(error),
                3 => client.revalidate(token).map(token_bytes).map_err(error),
                4 => client.release(token).map(|()| Vec::new()).map_err(error),
                _ => unreachable!(),
            }
        }
        _ => Err(malformed),
    }
}
fn main() {
    let mut b = Vec::new(); io::stdin().read_to_end(&mut b).unwrap();
    let (category, code, payload) = match execute(&b) { Ok(p) => (0u64, 0u64, p), Err((a, b)) => (a, b, Vec::new()) };
    let mut out = b"PLUR0001".to_vec();
    for n in [category, code, payload.len() as u64] { out.extend_from_slice(&n.to_le_bytes()); }
    out.extend_from_slice(&payload); io::stdout().write_all(&out).unwrap();
}
