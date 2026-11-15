use serde::{Deserialize,Serialize};
use std::{io::{Read,Write},net::{TcpStream,TcpListener},thread,time::{Duration,Instant}};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok:bool,msg:&str)->Result<()> { if ok {Ok(())} else {Err(msg.into())} }
#[allow(dead_code)]
mod baseline {
use super::*;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Submit {
        packet: String,
    },
    Head,
    History {
        tip: String,
        after: String,
    },
    PoolSubmitBundle {
        pool_context: String,
        transactions: Vec<String>,
    },
    PoolStatus,
    GrowthSubmitV1 {
        packet: String,
    },
    GrowthPacketStatusV1 {
        packet: String,
    },
    GrowthHeadV1,
}

pub const PROFILE: &str = "public-protected-development-v3";
const HELLO_BYTES: usize = 108;
const SOLUTION_BYTES: usize = 108;
const MAX_PACKET: usize = 1_048_576;
const MAX_BODY: usize = 2 * MAX_PACKET + 64;
const MAX_READ_BODY: usize = 512;
const MIN_POOL_RAW: usize = 159;
const MAX_POOL_RAW: usize = 2048;
const MAX_POOL_MEMBERS: usize = 16;
const MAX_POOL_BUNDLE_BYTES: usize = MAX_POOL_RAW * MAX_POOL_MEMBERS;
const MAX_POOL_BODY: usize = MAX_POOL_BUNDLE_BYTES * 2 + 512;
const MAX_SERVICE_SECONDS: u64 = 72 * 3600;
const MAX_RESPONSE: usize = 2 * MAX_PACKET + 4096;
const MAX_CONNECTIONS: usize = 64;
// Each active V3 listener starts three worker threads and bounded proof/read
// channels; cap aggregate count per already-pinned Node service domain.
const MAX_LISTENERS_PER_CPU_DOMAIN: usize = 4;
const MAX_PAID_BODY_BYTES: usize = 8 * 1024 * 1024;
// Reservations partition the existing totals; they add no socket/worker/queue.
const READ_BODY_RESERVE: usize = 128 * 1024;
const CONTROL_OUTPUT_RESERVE: usize = 512 * 1024;
const MAX_MUTATING_GRANTS: usize = 8;
const MAX_READ_GRANTS: usize = 8;
const MAX_SPENT: usize = 1024;
const MAX_HISTORY_STEPS: u64 = 1024;
const PREFIX_MS: u64 = 2000;
const CHALLENGE_MS: u64 = 2000;
const BODY_MS: u64 = 5000;
const OVERALL_MS: u64 = 30000;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const OUTPUT_MS: u64 = 5000;
const WORK_MS: u64 = 10_000;
const CHALLENGES_PER_SECOND: u64 = 128;
const CHALLENGE_BURST: u64 = 32;
const READ_CHALLENGE_RESERVE: u64 = 8;
const IO_QUANTUM: usize = 64 * 1024;

fn request_op(request: &Request) -> Result<u8> {
    match request {
        Request::Submit { .. } => Ok(1),
        Request::Head => Ok(2),
        Request::History { .. } => Ok(3),
        Request::PoolSubmitBundle { .. } => Ok(4),
        Request::PoolStatus => Ok(5),
        Request::GrowthSubmitV1 { .. } => Ok(6),
        Request::GrowthPacketStatusV1 { .. } => Ok(7),
        Request::GrowthHeadV1 => Ok(8),
    }
}
fn response_maximum(op: u8) -> usize {
    if op == 3 {
        MAX_RESPONSE
    } else {
        16384
    }
}
// Historical name denotes the paid resource lane; growth exact reads also pay.
fn mutating_operation(op: u8) -> bool {
    matches!(op, 1 | 4 | 6 | 7)
}
fn body_maximum(op: u8) -> Result<usize> {
    match op {
        1 | 6 | 7 => Ok(MAX_BODY),
        4 => Ok(MAX_POOL_BODY),
        2 | 3 | 5 | 8 => Ok(MAX_READ_BODY),
        _ => Err("PUBLIC_OPERATION".into()),
    }
}
fn lower_hex(text: &[u8]) -> bool {
    text.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
/// Check cardinality and every hex row before serde can allocate a Vec<String>.
fn pool_bundle_body_guard(bytes: &[u8]) -> Result<()> {
    ensure(bytes.len() <= MAX_POOL_BODY, "PUBLIC_POOL_BODY")?;
    let prefix = br#"{"op":"pool_submit_bundle","pool_context":""#;
    let payload = bytes
        .strip_prefix(prefix)
        .and_then(|b| b.strip_suffix(b"]}"))
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let (context, rest) = payload.split_at_checked(64).ok_or("PUBLIC_POOL_CONTEXT")?;
    ensure(lower_hex(context), "PUBLIC_POOL_CONTEXT")?;
    let mut rest = rest
        .strip_prefix(b"\",\"transactions\":[")
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let mut count = 0;
    let mut total = 0usize;
    while !rest.is_empty() {
        ensure(count < MAX_POOL_MEMBERS, "PUBLIC_POOL_MEMBERS")?;
        rest = rest.strip_prefix(b"\"").ok_or("PUBLIC_POOL_CANONICAL")?;
        let end = rest
            .iter()
            .position(|b| *b == b'"')
            .ok_or("PUBLIC_POOL_CANONICAL")?;
        let text = &rest[..end];
        ensure(
            text.len().is_multiple_of(2)
                && (2 * MIN_POOL_RAW..=2 * MAX_POOL_RAW).contains(&text.len())
                && lower_hex(text),
            "PUBLIC_POOL_RAW",
        )?;
        total = total
            .checked_add(text.len() / 2)
            .ok_or("PUBLIC_POOL_BYTES")?;
        ensure(total <= MAX_POOL_BUNDLE_BYTES, "PUBLIC_POOL_BYTES")?;
        count += 1;
        rest = &rest[end + 1..];
        if !rest.is_empty() {
            rest = rest.strip_prefix(b",").ok_or("PUBLIC_POOL_CANONICAL")?;
            ensure(!rest.is_empty(), "PUBLIC_POOL_CANONICAL")?;
        }
    }
    ensure(
        (1..=MAX_POOL_MEMBERS).contains(&count),
        "PUBLIC_POOL_MEMBERS",
    )
}

/// Streaming canonical equality avoids another body-sized serialization Vec.
struct ExactCanonical<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl Write for ExactCanonical<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical overflow"))?;
        if self.bytes.get(self.cursor..end) != Some(bytes) {
            return Err(std::io::Error::other("noncanonical request"));
        }
        self.cursor = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_request(bytes: &[u8], op: u8) -> Result<Request> {
    ensure(
        !bytes.is_empty() && bytes.len() <= body_maximum(op)?,
        "PUBLIC_BODY_LIMIT",
    )?;
    if op == 4 {
        pool_bundle_body_guard(bytes)?;
    }
    if matches!(op, 1 | 6 | 7) {
        // Every packet-bearing profile rejects noncanonical hex before allocation.
        let prefix: &[u8] = match op {
            1 => br#"{"op":"submit","packet":""#,
            6 => br#"{"op":"growth_submit_v1","packet":""#,
            7 => br#"{"op":"growth_packet_status_v1","packet":""#,
            _ => unreachable!(),
        };
        let text = bytes
            .strip_prefix(prefix)
            .and_then(|b| b.strip_suffix(br#""}"#))
            .ok_or("PUBLIC_REQUEST_CANONICAL")?;
        ensure(
            text.len() <= 2 * MAX_PACKET
                && text.len().is_multiple_of(2)
                && text
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "PUBLIC_PACKET_TEXT",
        )?;
    }
    let request: Request = serde_json::from_slice(bytes)?;
    let mut writer = ExactCanonical { bytes, cursor: 0 };
    serde_json::to_writer(&mut writer, &request).map_err(|_| "PUBLIC_REQUEST_CANONICAL")?;
    ensure(
        writer.cursor == bytes.len() && request_op(&request)? == op,
        "PUBLIC_REQUEST_CANONICAL",
    )?;
    Ok(request)
}

fn read_available(socket: &mut TcpStream, bytes: &mut Vec<u8>, expected: usize) -> Result<bool> {
    ensure(bytes.len() <= expected, "PUBLIC_READ_OVERFLOW")?;
    let remaining = expected - bytes.len();
    if remaining == 0 {
        return Ok(true);
    }
    let mut buffer = [0; IO_QUANTUM];
    match socket.read(&mut buffer[..remaining.min(IO_QUANTUM)]) {
        Ok(0) => Err("PUBLIC_EOF".into()),
        Ok(n) => {
            bytes.extend(&buffer[..n]);
            Ok(bytes.len() == expected)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod input_decode_tests {
//! Differential wire acceptance and actual nonblocking socket controls. These
//! are transport component checks, not the original four-second service gate.
use super::*;
use std::net::Shutdown;

fn packet_request(op: u8, packet: String) -> Request {
    match op {
        1 => Request::Submit { packet },
        6 => Request::GrowthSubmitV1 { packet },
        7 => Request::GrowthPacketStatusV1 { packet },
        _ => panic!("packet operation"),
    }
}

// Independent serde canonical oracle. The packet field's protocol grammar is
// applied to the parsed value; production establishes it directly on the wire.
fn serde_packet_oracle(bytes: &[u8], op: u8) -> Option<Request> {
    if bytes.is_empty() || bytes.len() > body_maximum(op).ok()? {
        return None;
    }
    let request: Request = serde_json::from_slice(bytes).ok()?;
    if request_op(&request).ok()? != op || serde_json::to_vec(&request).ok()? != bytes {
        return None;
    }
    let packet = match &request {
        Request::Submit { packet }
        | Request::GrowthSubmitV1 { packet }
        | Request::GrowthPacketStatusV1 { packet } => packet,
        _ => return None,
    };
    if packet.len() > 2 * MAX_PACKET
        || !packet.len().is_multiple_of(2)
        || packet.chars().any(|c| !matches!(c, '0'..='9' | 'a'..='f'))
    {
        return None;
    }
    Some(request)
}

#[test]
fn packet_envelopes_match_serde_for_every_single_byte_mutation_and_truncation() {
    for op in [1, 6, 7] {
        let raw = serde_json::to_vec(&packet_request(op, "0123456789abcdef".into())).unwrap();
        for position in 0..raw.len() {
            for value in 0..=u8::MAX {
                let mut changed = raw.clone();
                changed[position] = value;
                assert_eq!(
                    canonical_request(&changed, op).ok(),
                    serde_packet_oracle(&changed, op),
                    "operation {op}, byte {position}, value {value}"
                );
            }
            assert!(canonical_request(&raw[..position], op).is_err());
            let mut removed = raw.clone();
            removed.remove(position);
            assert_eq!(
                canonical_request(&removed, op).ok(),
                serde_packet_oracle(&removed, op),
                "operation {op}, removed byte {position}"
            );
        }
        for suffix in [b" ".as_slice(), b"\n", b"{}", b"\0"] {
            let mut changed = raw.clone();
            changed.extend_from_slice(suffix);
            assert!(canonical_request(&changed, op).is_err());
        }
    }
}

#[test]
fn packet_envelopes_keep_empty_exact_maximum_and_over_limit_behavior() {
    for op in [1, 6, 7] {
        for bytes in [0, 1, MAX_PACKET] {
            let request = packet_request(op, "ac".repeat(bytes));
            let raw = serde_json::to_vec(&request).unwrap();
            assert_eq!(canonical_request(&raw, op).unwrap(), request);
            assert_eq!(serde_packet_oracle(&raw, op), Some(request));
        }
        let raw = serde_json::to_vec(&packet_request(op, "ac".repeat(MAX_PACKET + 1))).unwrap();
        assert!(canonical_request(&raw, op).is_err());
        assert!(serde_packet_oracle(&raw, op).is_none());
    }
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (receiver, _) = listener.accept().unwrap();
    sender.set_nodelay(true).unwrap();
    receiver.set_nonblocking(true).unwrap();
    (sender, receiver)
}

fn receive_until(receiver: &mut TcpStream, bytes: &mut Vec<u8>, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !read_available(receiver, bytes, expected).unwrap() {
        assert!(
            Instant::now() < deadline,
            "local socket did not deliver bytes"
        );
        thread::yield_now();
    }
}

#[test]
fn initialized_socket_reads_preserve_partial_bytes_and_ignore_unreceived_padding() {
    let (mut sender, mut receiver) = socket_pair();
    let mut bytes = Vec::with_capacity(HELLO_BYTES);
    for _ in 0..32 {
        assert!(!read_available(&mut receiver, &mut bytes, HELLO_BYTES).unwrap());
        assert!(bytes.is_empty());
        assert_eq!(bytes.capacity(), HELLO_BYTES);
    }
    sender.write_all(b"abc").unwrap();
    receive_until(&mut receiver, &mut bytes, 3);
    assert_eq!(bytes, b"abc");
    assert!(!read_available(&mut receiver, &mut bytes, HELLO_BYTES).unwrap());
    assert_eq!(bytes, b"abc");
    sender.write_all(b"def").unwrap();
    receive_until(&mut receiver, &mut bytes, 6);
    assert_eq!(bytes, b"abcdef");
    // A completed frame never consumes the next frame's bytes.
    sender.write_all(b"next").unwrap();
    assert!(read_available(&mut receiver, &mut bytes, 6).unwrap());
    assert_eq!(bytes, b"abcdef");
    let mut next = Vec::with_capacity(4);
    receive_until(&mut receiver, &mut next, 4);
    assert_eq!(next, b"next");
    sender.shutdown(Shutdown::Write).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match read_available(&mut receiver, &mut bytes, HELLO_BYTES) {
            Err(error) => {
                assert_eq!(error.to_string(), "PUBLIC_EOF");
                break;
            }
            Ok(false) => assert!(Instant::now() < deadline),
            Ok(true) => panic!("unreceived padding was accepted"),
        }
    }
    assert_eq!(bytes, b"abcdef");
    assert_eq!(bytes.capacity(), HELLO_BYTES);
}

#[test]
fn initialized_socket_reads_retain_original_quantum_and_do_not_swallow_trailing_bytes() {
    let (mut sender, mut receiver) = socket_pair();
    let data: Vec<u8> = (0..IO_QUANTUM + 17).map(|i| i as u8).collect();
    sender.write_all(&data).unwrap();
    sender.write_all(b"tail").unwrap();
    let mut bytes = Vec::with_capacity(data.len());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let before = bytes.len();
        let complete = read_available(&mut receiver, &mut bytes, data.len()).unwrap();
        assert!(bytes.len() - before <= IO_QUANTUM);
        assert_eq!(&bytes, &data[..bytes.len()]);
        assert_eq!(bytes.capacity(), data.len());
        if complete {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    let mut tail = Vec::with_capacity(4);
    receive_until(&mut receiver, &mut tail, 4);
    assert_eq!(tail, b"tail");
    assert_eq!(bytes, data);
    let error = read_available(&mut receiver, &mut bytes, data.len() - 1).unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_READ_OVERFLOW");
    assert_eq!(bytes, data);
}

}
pub fn decode(raw: &[u8],op:u8) { std::hint::black_box(canonical_request(std::hint::black_box(raw),op).unwrap()); }
pub fn idle(socket: &mut TcpStream,bytes: &mut Vec<u8>) { assert!(!read_available(socket,bytes,108).unwrap()); }
}
#[allow(dead_code)]
mod candidate {
use super::*;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Submit {
        packet: String,
    },
    Head,
    History {
        tip: String,
        after: String,
    },
    PoolSubmitBundle {
        pool_context: String,
        transactions: Vec<String>,
    },
    PoolStatus,
    GrowthSubmitV1 {
        packet: String,
    },
    GrowthPacketStatusV1 {
        packet: String,
    },
    GrowthHeadV1,
}

pub const PROFILE: &str = "public-protected-development-v3";
const HELLO_BYTES: usize = 108;
const SOLUTION_BYTES: usize = 108;
const MAX_PACKET: usize = 1_048_576;
const MAX_BODY: usize = 2 * MAX_PACKET + 64;
const MAX_READ_BODY: usize = 512;
const MIN_POOL_RAW: usize = 159;
const MAX_POOL_RAW: usize = 2048;
const MAX_POOL_MEMBERS: usize = 16;
const MAX_POOL_BUNDLE_BYTES: usize = MAX_POOL_RAW * MAX_POOL_MEMBERS;
const MAX_POOL_BODY: usize = MAX_POOL_BUNDLE_BYTES * 2 + 512;
const MAX_SERVICE_SECONDS: u64 = 72 * 3600;
const MAX_RESPONSE: usize = 2 * MAX_PACKET + 4096;
const MAX_CONNECTIONS: usize = 64;
// Each active V3 listener starts three worker threads and bounded proof/read
// channels; cap aggregate count per already-pinned Node service domain.
const MAX_LISTENERS_PER_CPU_DOMAIN: usize = 4;
const MAX_PAID_BODY_BYTES: usize = 8 * 1024 * 1024;
// Reservations partition the existing totals; they add no socket/worker/queue.
const READ_BODY_RESERVE: usize = 128 * 1024;
const CONTROL_OUTPUT_RESERVE: usize = 512 * 1024;
const MAX_MUTATING_GRANTS: usize = 8;
const MAX_READ_GRANTS: usize = 8;
const MAX_SPENT: usize = 1024;
const MAX_HISTORY_STEPS: u64 = 1024;
const PREFIX_MS: u64 = 2000;
const CHALLENGE_MS: u64 = 2000;
const BODY_MS: u64 = 5000;
const OVERALL_MS: u64 = 30000;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const OUTPUT_MS: u64 = 5000;
const WORK_MS: u64 = 10_000;
const CHALLENGES_PER_SECOND: u64 = 128;
const CHALLENGE_BURST: u64 = 32;
const READ_CHALLENGE_RESERVE: u64 = 8;
const IO_QUANTUM: usize = 64 * 1024;

fn request_op(request: &Request) -> Result<u8> {
    match request {
        Request::Submit { .. } => Ok(1),
        Request::Head => Ok(2),
        Request::History { .. } => Ok(3),
        Request::PoolSubmitBundle { .. } => Ok(4),
        Request::PoolStatus => Ok(5),
        Request::GrowthSubmitV1 { .. } => Ok(6),
        Request::GrowthPacketStatusV1 { .. } => Ok(7),
        Request::GrowthHeadV1 => Ok(8),
    }
}
fn response_maximum(op: u8) -> usize {
    if op == 3 {
        MAX_RESPONSE
    } else {
        16384
    }
}
// Historical name denotes the paid resource lane; growth exact reads also pay.
fn mutating_operation(op: u8) -> bool {
    matches!(op, 1 | 4 | 6 | 7)
}
fn body_maximum(op: u8) -> Result<usize> {
    match op {
        1 | 6 | 7 => Ok(MAX_BODY),
        4 => Ok(MAX_POOL_BODY),
        2 | 3 | 5 | 8 => Ok(MAX_READ_BODY),
        _ => Err("PUBLIC_OPERATION".into()),
    }
}
fn lower_hex(text: &[u8]) -> bool {
    text.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
/// Check cardinality and every hex row before serde can allocate a Vec<String>.
fn pool_bundle_body_guard(bytes: &[u8]) -> Result<()> {
    ensure(bytes.len() <= MAX_POOL_BODY, "PUBLIC_POOL_BODY")?;
    let prefix = br#"{"op":"pool_submit_bundle","pool_context":""#;
    let payload = bytes
        .strip_prefix(prefix)
        .and_then(|b| b.strip_suffix(b"]}"))
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let (context, rest) = payload.split_at_checked(64).ok_or("PUBLIC_POOL_CONTEXT")?;
    ensure(lower_hex(context), "PUBLIC_POOL_CONTEXT")?;
    let mut rest = rest
        .strip_prefix(b"\",\"transactions\":[")
        .ok_or("PUBLIC_POOL_CANONICAL")?;
    let mut count = 0;
    let mut total = 0usize;
    while !rest.is_empty() {
        ensure(count < MAX_POOL_MEMBERS, "PUBLIC_POOL_MEMBERS")?;
        rest = rest.strip_prefix(b"\"").ok_or("PUBLIC_POOL_CANONICAL")?;
        let end = rest
            .iter()
            .position(|b| *b == b'"')
            .ok_or("PUBLIC_POOL_CANONICAL")?;
        let text = &rest[..end];
        ensure(
            text.len().is_multiple_of(2)
                && (2 * MIN_POOL_RAW..=2 * MAX_POOL_RAW).contains(&text.len())
                && lower_hex(text),
            "PUBLIC_POOL_RAW",
        )?;
        total = total
            .checked_add(text.len() / 2)
            .ok_or("PUBLIC_POOL_BYTES")?;
        ensure(total <= MAX_POOL_BUNDLE_BYTES, "PUBLIC_POOL_BYTES")?;
        count += 1;
        rest = &rest[end + 1..];
        if !rest.is_empty() {
            rest = rest.strip_prefix(b",").ok_or("PUBLIC_POOL_CANONICAL")?;
            ensure(!rest.is_empty(), "PUBLIC_POOL_CANONICAL")?;
        }
    }
    ensure(
        (1..=MAX_POOL_MEMBERS).contains(&count),
        "PUBLIC_POOL_MEMBERS",
    )
}

/// Streaming canonical equality avoids another body-sized serialization Vec.
struct ExactCanonical<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl Write for ExactCanonical<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical overflow"))?;
        if self.bytes.get(self.cursor..end) != Some(bytes) {
            return Err(std::io::Error::other("noncanonical request"));
        }
        self.cursor = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_request(bytes: &[u8], op: u8) -> Result<Request> {
    ensure(
        !bytes.is_empty() && bytes.len() <= body_maximum(op)?,
        "PUBLIC_BODY_LIMIT",
    )?;
    if op == 4 {
        pool_bundle_body_guard(bytes)?;
    }
    if matches!(op, 1 | 6 | 7) {
        // Every packet-bearing profile rejects noncanonical hex before allocation.
        let prefix: &[u8] = match op {
            1 => br#"{"op":"submit","packet":""#,
            6 => br#"{"op":"growth_submit_v1","packet":""#,
            7 => br#"{"op":"growth_packet_status_v1","packet":""#,
            _ => unreachable!(),
        };
        let text = bytes
            .strip_prefix(prefix)
            .and_then(|b| b.strip_suffix(br#""}"#))
            .ok_or("PUBLIC_REQUEST_CANONICAL")?;
        ensure(
            text.len() <= 2 * MAX_PACKET && text.len().is_multiple_of(2) && lower_hex(text),
            "PUBLIC_PACKET_TEXT",
        )?;
        // The exact envelope and complete lowercase ASCII grammar already
        // establish the same serde representation. Avoid a second JSON parse
        // and streaming re-serialization of this potentially 2-MiB string.
        // Nothing has established Packet, Work, current owner or State validity;
        // those original checks still execute after this transport-only decode.
        let packet = std::str::from_utf8(text)
            .map_err(|_| "PUBLIC_PACKET_TEXT")?
            .to_owned();
        return Ok(match op {
            1 => Request::Submit { packet },
            6 => Request::GrowthSubmitV1 { packet },
            7 => Request::GrowthPacketStatusV1 { packet },
            _ => unreachable!(),
        });
    }
    let request: Request = serde_json::from_slice(bytes)?;
    let mut writer = ExactCanonical { bytes, cursor: 0 };
    serde_json::to_writer(&mut writer, &request).map_err(|_| "PUBLIC_REQUEST_CANONICAL")?;
    ensure(
        writer.cursor == bytes.len() && request_op(&request)? == op,
        "PUBLIC_REQUEST_CANONICAL",
    )?;
    Ok(request)
}

fn read_available(socket: &mut TcpStream, bytes: &mut Vec<u8>, expected: usize) -> Result<bool> {
    ensure(bytes.len() <= expected, "PUBLIC_READ_OVERFLOW")?;
    let remaining = expected - bytes.len();
    if remaining == 0 {
        return Ok(true);
    }
    // Hello/Solution and paid Body already own their bounded capacity. Read
    // into that initialized storage instead of zeroing a 64-KiB temporary for
    // every small/idle frame and then copying each received byte a second time.
    // Truncate on every outcome: unreceived padding never becomes input and
    // observation counters continue to report only actual received bytes.
    let before = bytes.len();
    let limit = remaining.min(IO_QUANTUM);
    bytes.resize(before + limit, 0);
    let result = socket.read(&mut bytes[before..]);
    let received = result.as_ref().copied().unwrap_or(0);
    bytes.truncate(before + received);
    match result {
        Ok(0) => Err("PUBLIC_EOF".into()),
        Ok(_) => Ok(bytes.len() == expected),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod input_decode_tests {
//! Differential wire acceptance and actual nonblocking socket controls. These
//! are transport component checks, not the original four-second service gate.
use super::*;
use std::net::Shutdown;

fn packet_request(op: u8, packet: String) -> Request {
    match op {
        1 => Request::Submit { packet },
        6 => Request::GrowthSubmitV1 { packet },
        7 => Request::GrowthPacketStatusV1 { packet },
        _ => panic!("packet operation"),
    }
}

// Independent serde canonical oracle. The packet field's protocol grammar is
// applied to the parsed value; production establishes it directly on the wire.
fn serde_packet_oracle(bytes: &[u8], op: u8) -> Option<Request> {
    if bytes.is_empty() || bytes.len() > body_maximum(op).ok()? {
        return None;
    }
    let request: Request = serde_json::from_slice(bytes).ok()?;
    if request_op(&request).ok()? != op || serde_json::to_vec(&request).ok()? != bytes {
        return None;
    }
    let packet = match &request {
        Request::Submit { packet }
        | Request::GrowthSubmitV1 { packet }
        | Request::GrowthPacketStatusV1 { packet } => packet,
        _ => return None,
    };
    if packet.len() > 2 * MAX_PACKET
        || !packet.len().is_multiple_of(2)
        || packet.chars().any(|c| !matches!(c, '0'..='9' | 'a'..='f'))
    {
        return None;
    }
    Some(request)
}

#[test]
fn packet_envelopes_match_serde_for_every_single_byte_mutation_and_truncation() {
    for op in [1, 6, 7] {
        let raw = serde_json::to_vec(&packet_request(op, "0123456789abcdef".into())).unwrap();
        for position in 0..raw.len() {
            for value in 0..=u8::MAX {
                let mut changed = raw.clone();
                changed[position] = value;
                assert_eq!(
                    canonical_request(&changed, op).ok(),
                    serde_packet_oracle(&changed, op),
                    "operation {op}, byte {position}, value {value}"
                );
            }
            assert!(canonical_request(&raw[..position], op).is_err());
            let mut removed = raw.clone();
            removed.remove(position);
            assert_eq!(
                canonical_request(&removed, op).ok(),
                serde_packet_oracle(&removed, op),
                "operation {op}, removed byte {position}"
            );
        }
        for suffix in [b" ".as_slice(), b"\n", b"{}", b"\0"] {
            let mut changed = raw.clone();
            changed.extend_from_slice(suffix);
            assert!(canonical_request(&changed, op).is_err());
        }
    }
}

#[test]
fn packet_envelopes_keep_empty_exact_maximum_and_over_limit_behavior() {
    for op in [1, 6, 7] {
        for bytes in [0, 1, MAX_PACKET] {
            let request = packet_request(op, "ac".repeat(bytes));
            let raw = serde_json::to_vec(&request).unwrap();
            assert_eq!(canonical_request(&raw, op).unwrap(), request);
            assert_eq!(serde_packet_oracle(&raw, op), Some(request));
        }
        let raw = serde_json::to_vec(&packet_request(op, "ac".repeat(MAX_PACKET + 1))).unwrap();
        assert!(canonical_request(&raw, op).is_err());
        assert!(serde_packet_oracle(&raw, op).is_none());
    }
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (receiver, _) = listener.accept().unwrap();
    sender.set_nodelay(true).unwrap();
    receiver.set_nonblocking(true).unwrap();
    (sender, receiver)
}

fn receive_until(receiver: &mut TcpStream, bytes: &mut Vec<u8>, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !read_available(receiver, bytes, expected).unwrap() {
        assert!(
            Instant::now() < deadline,
            "local socket did not deliver bytes"
        );
        thread::yield_now();
    }
}

#[test]
fn initialized_socket_reads_preserve_partial_bytes_and_ignore_unreceived_padding() {
    let (mut sender, mut receiver) = socket_pair();
    let mut bytes = Vec::with_capacity(HELLO_BYTES);
    for _ in 0..32 {
        assert!(!read_available(&mut receiver, &mut bytes, HELLO_BYTES).unwrap());
        assert!(bytes.is_empty());
        assert_eq!(bytes.capacity(), HELLO_BYTES);
    }
    sender.write_all(b"abc").unwrap();
    receive_until(&mut receiver, &mut bytes, 3);
    assert_eq!(bytes, b"abc");
    assert!(!read_available(&mut receiver, &mut bytes, HELLO_BYTES).unwrap());
    assert_eq!(bytes, b"abc");
    sender.write_all(b"def").unwrap();
    receive_until(&mut receiver, &mut bytes, 6);
    assert_eq!(bytes, b"abcdef");
    // A completed frame never consumes the next frame's bytes.
    sender.write_all(b"next").unwrap();
    assert!(read_available(&mut receiver, &mut bytes, 6).unwrap());
    assert_eq!(bytes, b"abcdef");
    let mut next = Vec::with_capacity(4);
    receive_until(&mut receiver, &mut next, 4);
    assert_eq!(next, b"next");
    sender.shutdown(Shutdown::Write).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match read_available(&mut receiver, &mut bytes, HELLO_BYTES) {
            Err(error) => {
                assert_eq!(error.to_string(), "PUBLIC_EOF");
                break;
            }
            Ok(false) => assert!(Instant::now() < deadline),
            Ok(true) => panic!("unreceived padding was accepted"),
        }
    }
    assert_eq!(bytes, b"abcdef");
    assert_eq!(bytes.capacity(), HELLO_BYTES);
}

#[test]
fn initialized_socket_reads_retain_original_quantum_and_do_not_swallow_trailing_bytes() {
    let (mut sender, mut receiver) = socket_pair();
    let data: Vec<u8> = (0..IO_QUANTUM + 17).map(|i| i as u8).collect();
    sender.write_all(&data).unwrap();
    sender.write_all(b"tail").unwrap();
    let mut bytes = Vec::with_capacity(data.len());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let before = bytes.len();
        let complete = read_available(&mut receiver, &mut bytes, data.len()).unwrap();
        assert!(bytes.len() - before <= IO_QUANTUM);
        assert_eq!(&bytes, &data[..bytes.len()]);
        assert_eq!(bytes.capacity(), data.len());
        if complete {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    let mut tail = Vec::with_capacity(4);
    receive_until(&mut receiver, &mut tail, 4);
    assert_eq!(tail, b"tail");
    assert_eq!(bytes, data);
    let error = read_available(&mut receiver, &mut bytes, data.len() - 1).unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_READ_OVERFLOW");
    assert_eq!(bytes, data);
}

}
pub fn decode(raw: &[u8],op:u8) { std::hint::black_box(canonical_request(std::hint::black_box(raw),op).unwrap()); }
pub fn idle(socket: &mut TcpStream,bytes: &mut Vec<u8>) { assert!(!read_available(socket,bytes,108).unwrap()); }
}
fn main() {
for op in [1u8,6,7] {
let name = match op {1=>"submit",6=>"growth_submit_v1",_=>"growth_packet_status_v1"};
for size in [64usize,49_603,1_048_576] {
let raw=format!("{{\"op\":\"{}\",\"packet\":\"{}\"}}",name,"ac".repeat(size)).into_bytes();
let count= (16_777_216usize/raw.len()).max(4);
for arm in [0,1,1,0] {
let started=Instant::now();
for _ in 0..count { if arm==0 {baseline::decode(&raw,op)} else {candidate::decode(&raw,op)} }
println!("{{\"kind\":\"canonical_decode\",\"op\":{},\"packet_bytes\":{},\"calls\":{},\"arm\":{},\"wall_ns\":{}}}",op,size,count,arm,started.elapsed().as_nanos());
}
}
}
let listener=TcpListener::bind("127.0.0.1:0").unwrap();
let _sender=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
let (mut receiver,_)=listener.accept().unwrap(); receiver.set_nonblocking(true).unwrap();
for arm in [0,1,1,0] {
let mut bytes=Vec::with_capacity(108); let started=Instant::now();
for _ in 0..100_000 { if arm==0 {baseline::idle(&mut receiver,&mut bytes)} else {candidate::idle(&mut receiver,&mut bytes)} }
println!("{{\"kind\":\"idle_hello_socket\",\"calls\":100000,\"arm\":{},\"wall_ns\":{}}}",arm,started.elapsed().as_nanos());
}
}
