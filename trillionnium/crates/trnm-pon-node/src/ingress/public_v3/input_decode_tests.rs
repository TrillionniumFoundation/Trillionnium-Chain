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

fn compare_borrowed_submit_grammar(bytes: &[u8], op: u8) {
    if op == 1 {
        assert_eq!(
            CanonicalPacketText::from_body(bytes)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            canonical_request(bytes, op)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            "borrowed Submit must keep the independent original grammar and errors"
        );
    }
}

#[test]
fn packet_envelopes_match_serde_for_every_single_byte_mutation_and_truncation() {
    for op in [1, 6, 7] {
        let raw = serde_json::to_vec(&packet_request(op, "0123456789abcdef".into())).unwrap();
        for position in 0..raw.len() {
            for value in 0..=u8::MAX {
                let mut changed = raw.clone();
                changed[position] = value;
                compare_borrowed_submit_grammar(&changed, op);
                assert_eq!(
                    canonical_request(&changed, op).ok(),
                    serde_packet_oracle(&changed, op),
                    "operation {op}, byte {position}, value {value}"
                );
            }
            compare_borrowed_submit_grammar(&raw[..position], op);
            assert!(canonical_request(&raw[..position], op).is_err());
            let mut removed = raw.clone();
            removed.remove(position);
            compare_borrowed_submit_grammar(&removed, op);
            assert_eq!(
                canonical_request(&removed, op).ok(),
                serde_packet_oracle(&removed, op),
                "operation {op}, removed byte {position}"
            );
        }
        for suffix in [b" ".as_slice(), b"\n", b"{}", b"\0"] {
            let mut changed = raw.clone();
            changed.extend_from_slice(suffix);
            compare_borrowed_submit_grammar(&changed, op);
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
            compare_borrowed_submit_grammar(&raw, op);
            assert_eq!(canonical_request(&raw, op).unwrap(), request);
            assert_eq!(serde_packet_oracle(&raw, op), Some(request));
        }
        let raw = serde_json::to_vec(&packet_request(op, "ac".repeat(MAX_PACKET + 1))).unwrap();
        compare_borrowed_submit_grammar(&raw, op);
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

// Retained streaming reference and finite error-order controls from the
// historical arithmetic candidate. These call only the current in-memory decoder;
// they do not execute the historical CPU observation or socket controls.
fn canonical_packet_reference(bytes: &[u8], op: u8) -> Result<Request> {
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

fn compare_packet_decoder(bytes: &[u8], op: u8) {
    let reference = canonical_packet_reference(bytes, op).map_err(|error| error.to_string());
    let actual = canonical_request(bytes, op).map_err(|error| error.to_string());
    assert_eq!(actual, reference, "op={op}, body_len={}", bytes.len());
}

#[test]
fn canonical_packet_decoder_matches_streamed_parent_for_every_single_byte_mutation() {
    for request in [
        Request::Submit {
            packet: "01abef".into(),
        },
        Request::GrowthSubmitV1 {
            packet: "01abef".into(),
        },
        Request::GrowthPacketStatusV1 {
            packet: "01abef".into(),
        },
    ] {
        let op = request_op(&request).unwrap();
        let raw = serde_json::to_vec(&request).unwrap();
        compare_packet_decoder(&raw, op);
        for position in 0..raw.len() {
            let mut changed = raw.clone();
            for value in 0..=u8::MAX {
                changed[position] = value;
                compare_packet_decoder(&changed, op);
            }
            compare_packet_decoder(&raw[..position], op);
        }
        for position in 0..=raw.len() {
            for byte in [b' ', b'\n', b'"', b'\\', b'{', b'}', b',', 0, 0xff] {
                let mut changed = raw.clone();
                changed.insert(position, byte);
                compare_packet_decoder(&changed, op);
            }
        }
        for wrong_op in [1, 6, 7].into_iter().filter(|other| *other != op) {
            compare_packet_decoder(&raw, wrong_op);
        }
    }
}

#[test]
fn canonical_packet_decoder_preserves_empty_maximum_and_structural_refusals() {
    for op in [1, 6, 7] {
        for length in [
            0,
            1,
            2 * MAX_PACKET,
            2 * MAX_PACKET + 1,
            2 * MAX_PACKET + 2,
            MAX_BODY,
        ] {
            let packet = "a".repeat(length);
            let request = match op {
                1 => Request::Submit { packet },
                6 => Request::GrowthSubmitV1 { packet },
                7 => Request::GrowthPacketStatusV1 { packet },
                _ => unreachable!(),
            };
            compare_packet_decoder(&serde_json::to_vec(&request).unwrap(), op);
        }
    }
    for bytes in [
        br#"{"op":"submit","packet":"\u0061a"}"#.as_slice(),
        br#"{"op":"submit","packet":"aa","packet":"aa"}"#,
        br#"{"op":"submit","packet":"aa","authority":true}"#,
        br#"{"packet":"aa","op":"submit"}"#,
        br#"{"op":"submit","packet":"aa"}{}"#,
        br#"{"op":"submit","packet":"aa"} "#,
        br#"{"op":"submit","packet":"aA"}"#,
        br#"{"op":"submit","packet":null}"#,
    ] {
        compare_packet_decoder(bytes, 1);
    }
}
