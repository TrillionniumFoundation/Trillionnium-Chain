use super::*;
use crate::cell::{CellChunkV1, CellContextV1, CellManifestV1};
use std::thread;

fn binding() -> CellBep52BindingV1 {
    let context = CellContextV1 {
        family: "dht-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let hash = Sha256::digest(b"DHT hints never authorize this content").into();
    let manifest = CellManifestV1::new(
        context.clone(),
        38,
        hash,
        16_384,
        vec![CellChunkV1 {
            size: 38,
            sha256: hash,
        }],
    )
    .unwrap();
    CellBep52BindingV1::from_pinned_manifest(&manifest, manifest.id(), &context).unwrap()
}

fn session() -> CellBep52PeerSessionV1 {
    CellBep52PeerSessionV1::new(
        [41; 32],
        CellBep52PeerLimitsV1 {
            deadline: Instant::now() + Duration::from_secs(5),
            request_timeout: Duration::from_millis(500),
            max_connections: 8,
            max_received_bytes: 8 * 65_536,
            max_sent_bytes: 8192,
            max_messages: 32,
        },
    )
    .unwrap()
}

fn serve(
    task: impl FnOnce(UdpSocket, Vec<u8>, SocketAddr) + Send + 'static,
) -> (SocketAddrV4, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    let thread = thread::spawn(move || {
        let mut query = vec![0; 1200];
        let (count, caller) = socket.recv_from(&mut query).unwrap();
        query.truncate(count);
        task(socket, query, caller);
    });
    (address, thread)
}

fn peers(transaction: [u8; 8], contacts: &[[u8; 6]]) -> Vec<u8> {
    let mut response = b"d1:rd2:id20:012345678901234567895:token1:t6:valuesl".to_vec();
    for contact in contacts {
        response.extend(b"6:");
        response.extend(contact);
    }
    response.extend(b"ee1:t8:");
    response.extend(transaction);
    response.extend(b"1:y1:re");
    response
}

#[test]
fn udp_readonly_get_peers_pins_query_source_transaction_and_returns_hints_only() {
    let binding = binding();
    let pin = binding.info_hash();
    let (address, server) = serve(move |socket, query, caller| {
        let (value, used) = decode(&query).unwrap();
        assert_eq!(used, query.len());
        assert_eq!(value.field(b"q").unwrap().bytes().unwrap(), b"get_peers");
        assert_eq!(value.number(b"ro").unwrap(), 1);
        assert_eq!(
            value
                .field(b"a")
                .unwrap()
                .field(b"info_hash")
                .unwrap()
                .bytes()
                .unwrap(),
            &pin[..20]
        );
        assert_eq!(value.field(b"t").unwrap().bytes().unwrap(), [7; 8]);
        socket
            .send_to(&peers([7; 8], &[[127, 0, 0, 1, 0x1a, 0xe1]]), caller)
            .unwrap();
    });
    let mut session = session();
    let report =
        query_cell_bep52_dht_peers(&binding, address, [6; 20], [7; 8], &mut session).unwrap();
    server.join().unwrap();
    assert_eq!(report.info_hash, binding.info_hash());
    assert_eq!(
        report.peer_candidates,
        vec!["127.0.0.1:6881".parse().unwrap()]
    );
    assert_eq!(session.usage().dht_query_attempts, 1);
    assert_eq!(session.usage().connection_attempts, 0);
    assert_eq!(session.usage().completed_fetches, 0);
    assert_eq!(session.usage().refused_dht_queries, 0);
    assert_eq!(session.usage().received_messages, 1);
    assert_eq!(session.usage().sent_messages, 1);
}

#[test]
fn udp_source_mismatch_cannot_supply_a_matching_transaction() {
    let (address, server) = serve(move |socket, _, caller| {
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other
            .send_to(&peers([7; 8], &[[1, 2, 3, 4, 0, 80]]), caller)
            .unwrap();
        socket
            .send_to(&peers([7; 8], &[[127, 0, 0, 1, 0x1a, 0xe1]]), caller)
            .unwrap();
    });
    let mut session = session();
    let report =
        query_cell_bep52_dht_peers(&binding(), address, [6; 20], [7; 8], &mut session).unwrap();
    server.join().unwrap();
    assert_eq!(
        report.peer_candidates,
        vec!["127.0.0.1:6881".parse().unwrap()]
    );
    assert_eq!(
        session.usage().received_bytes,
        peers([7; 8], &[[127, 0, 0, 1, 0x1a, 0xe1]]).len() as u64
    );
}

#[test]
fn udp_wrong_transaction_and_errors_are_refused_with_full_response_accounting() {
    for response in [
        peers([8; 8], &[]),
        b"d1:eli203e3:bade1:t8:\x07\x07\x07\x07\x07\x07\x07\x071:y1:ee".to_vec(),
    ] {
        let count = response.len();
        let (address, server) = serve(move |socket, _, caller| {
            socket.send_to(&response, caller).unwrap();
        });
        let mut session = session();
        assert!(
            query_cell_bep52_dht_peers(&binding(), address, [6; 20], [7; 8], &mut session).is_err()
        );
        server.join().unwrap();
        assert_eq!(session.usage().received_bytes, count as u64);
        assert_eq!(session.usage().refused_dht_queries, 1);
        assert_eq!(session.refusals().len(), 1);
    }
}

#[test]
fn udp_oversize_datagram_is_counted_completely_then_refused() {
    let (address, server) = serve(move |socket, _, caller| {
        socket.send_to(&vec![b'x'; 16_384], caller).unwrap();
    });
    let mut session = session();
    assert!(
        query_cell_bep52_dht_peers(&binding(), address, [6; 20], [7; 8], &mut session).is_err()
    );
    server.join().unwrap();
    assert_eq!(session.usage().received_bytes, 16_384);
    assert_eq!(session.usage().refused_dht_queries, 1);
}

#[test]
fn udp_node_candidates_are_bounded_and_never_followed() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    silent
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let SocketAddr::V4(candidate) = silent.local_addr().unwrap() else {
        unreachable!()
    };
    let (address, server) = serve(move |socket, _, caller| {
        let mut response = b"d1:rd2:id20:012345678901234567895:nodes26:".to_vec();
        response.extend([4; 20]);
        response.extend(candidate.ip().octets());
        response.extend(candidate.port().to_be_bytes());
        response.extend(b"5:token1:te1:t8:");
        response.extend([7; 8]);
        response.extend(b"1:y1:re");
        socket.send_to(&response, caller).unwrap();
    });
    let mut session = session();
    let report =
        query_cell_bep52_dht_peers(&binding(), address, [6; 20], [7; 8], &mut session).unwrap();
    server.join().unwrap();
    assert_eq!(report.closer_node_candidates[0].endpoint, candidate);
    assert!(report.peer_candidates.is_empty());
    assert!(silent.recv_from(&mut [0; 1200]).is_err());
    assert_eq!(session.usage().dht_query_attempts, 1);
}

#[test]
fn udp_retry_identity_budget_and_original_expiry_do_not_reset() {
    let (address, server) = serve(move |socket, _, caller| {
        socket.send_to(&peers([7; 8], &[]), caller).unwrap();
    });
    let mut session = session();
    let binding = binding();
    query_cell_bep52_dht_peers(&binding, address, [6; 20], [7; 8], &mut session).unwrap();
    server.join().unwrap();
    let before = session.usage().clone();
    assert!(query_cell_bep52_dht_peers(&binding, address, [6; 20], [7; 8], &mut session).is_err());
    assert_eq!(*session.usage(), before);
    session.limits.max_received_bytes = session.usage().received_bytes + 65_535;
    assert!(query_cell_bep52_dht_peers(&binding, address, [6; 20], [8; 8], &mut session).is_err());
    assert_eq!(*session.usage(), before);
    session.limits.deadline = Instant::now();
    assert!(query_cell_bep52_dht_peers(&binding, address, [6; 20], [9; 8], &mut session).is_err());
    assert_eq!(*session.usage(), before);
}

#[test]
fn udp_compact_candidate_caps_duplicate_shape_and_noncanonical_bytes_are_refused() {
    let binding = binding();
    let address = "127.0.0.1:6881".parse().unwrap();
    for values in [
        vec![[127, 0, 0, 1, 0, 1]; 2],
        vec![[0, 0, 0, 0, 0, 1]],
        vec![[224, 0, 0, 1, 0, 1]],
        vec![[127, 0, 0, 1, 0, 0]],
        (1..=33).map(|i| [127, 0, 0, 1, 0, i]).collect(),
    ] {
        assert!(
            parse_response(&peers([7; 8], &values), &binding, address, [7; 8], [41; 32]).is_err()
        );
    }
    let mut valid = peers([7; 8], &[]);
    valid.extend(b"trailing");
    assert!(parse_response(&valid, &binding, address, [7; 8], [41; 32]).is_err());
    assert!(parse_response(
        b"d1:rd2:id20:012345678901234567895:nodes1:x5:token1:te1:t8:123456781:y1:re",
        &binding,
        address,
        *b"12345678",
        [41; 32]
    )
    .is_err());
}
