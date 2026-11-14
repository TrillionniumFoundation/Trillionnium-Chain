use super::*;
use crate::cell::{CellChunkV1, CellContextV1, CellManifestV1};
use std::{net::TcpListener, thread};

fn binding() -> CellBep52BindingV1 {
    let context = CellContextV1 {
        family: "dht-lookup-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let bytes = b"DHT discovery is never model authority";
    let hash = Sha256::digest(bytes).into();
    let manifest = CellManifestV1::new(
        context.clone(),
        bytes.len() as u64,
        hash,
        16_384,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
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

fn socket() -> (SocketAddrV4, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    (address, socket)
}

fn compact(endpoint: SocketAddrV4) -> [u8; 6] {
    let mut bytes = [0; 6];
    bytes[..4].copy_from_slice(&endpoint.ip().octets());
    bytes[4..].copy_from_slice(&endpoint.port().to_be_bytes());
    bytes
}

fn response(
    transaction: [u8; 8],
    id: [u8; 20],
    nodes: &[([u8; 20], SocketAddrV4)],
    peers: &[SocketAddrV4],
) -> Vec<u8> {
    let mut bytes = b"d1:rd2:id20:".to_vec();
    bytes.extend(id);
    bytes.extend(format!("5:nodes{}:", nodes.len() * 26).as_bytes());
    for (node, endpoint) in nodes {
        bytes.extend(node);
        bytes.extend(compact(*endpoint));
    }
    bytes.extend(b"5:token1:t6:valuesl");
    for endpoint in peers {
        bytes.extend(b"6:");
        bytes.extend(compact(*endpoint));
    }
    bytes.extend(b"ee1:t8:");
    bytes.extend(transaction);
    bytes.extend(b"1:y1:re");
    bytes
}

fn serve(
    socket: UdpSocket,
    id: [u8; 20],
    nodes: Vec<([u8; 20], SocketAddrV4)>,
    peers: Vec<SocketAddrV4>,
) -> thread::JoinHandle<usize> {
    thread::spawn(move || {
        let mut query = [0; 1200];
        let (count, caller) = socket.recv_from(&mut query).unwrap();
        let (value, used) = decode(&query[..count]).unwrap();
        assert_eq!(used, count);
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
            &binding().info_hash()[..20]
        );
        let transaction = value
            .field(b"t")
            .unwrap()
            .bytes()
            .unwrap()
            .try_into()
            .unwrap();
        let reply = response(transaction, id, &nodes, &peers);
        socket.send_to(&reply, caller).unwrap();
        reply.len()
    })
}

fn assert_silent(socket: &UdpSocket) {
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 1200]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn lookup_follows_admitted_second_hop_without_dialling_tcp_or_unlisted_nodes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let SocketAddr::V4(peer) = listener.local_addr().unwrap() else {
        unreachable!()
    };
    // Reserve the same UDP port so ephemeral node sockets cannot accidentally
    // equal the returned TCP endpoint (the policy includes exact IP/port).
    let peer_udp = UdpSocket::bind(peer).unwrap();
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let (unlisted, unlisted_socket) = socket();
    let first_server = serve(
        first_socket,
        [1; 20],
        vec![([2; 20], second), ([3; 20], unlisted)],
        vec![unlisted],
    );
    let second_server = serve(second_socket, [2; 20], vec![], vec![peer]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, second, peer]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    let bytes = first_server.join().unwrap() + second_server.join().unwrap();
    assert_eq!(report.info_hash, binding().info_hash());
    assert_eq!(report.operation_id, session.operation_id());
    assert_eq!(report.queried_endpoints, vec![first, second]);
    assert_eq!(report.peer_candidates, vec![peer]);
    assert_eq!(report.successful_queries, 2);
    assert_eq!(report.rejected_candidates, 2);
    assert_eq!(report.stop, CellBep52DhtLookupStopV1::FrontierExhausted);
    assert_eq!(session.usage().received_bytes, bytes as u64);
    assert_eq!(session.usage().dht_query_attempts, 2);
    assert_eq!(session.usage().connection_attempts, 0);
    assert_eq!(session.usage().completed_fetches, 0);
    assert_silent(&unlisted_socket);
    assert_silent(&peer_udp);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn lookup_uses_xor_distance_and_never_exceeds_query_ids() {
    let (first, first_socket) = socket();
    let (near, near_socket) = socket();
    let (far, far_socket) = socket();
    let near_id: [u8; 20] = binding().info_hash()[..20].try_into().unwrap();
    let far_id = near_id.map(|byte| byte ^ 255);
    let first_server = serve(
        first_socket,
        [1; 20],
        vec![(far_id, far), (near_id, near)],
        vec![],
    );
    let near_server = serve(near_socket, near_id, vec![], vec![]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, near, far]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    first_server.join().unwrap();
    near_server.join().unwrap();
    assert_eq!(report.queried_endpoints, vec![first, near]);
    assert_eq!(report.stop, CellBep52DhtLookupStopV1::QueryLimit);
    assert_eq!(session.usage().dht_query_attempts, 2);
    assert_silent(&far_socket);
}

#[test]
fn lookup_deduplicates_cycles_and_advertised_node_aliases() {
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let (alias, alias_socket) = socket();
    let first_server = serve(first_socket, [1; 20], vec![([2; 20], second)], vec![]);
    let second_server = serve(
        second_socket,
        [2; 20],
        vec![([1; 20], first), ([2; 20], alias)],
        vec![],
    );
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, second, alias]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8], [9; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    first_server.join().unwrap();
    second_server.join().unwrap();
    assert_eq!(report.queried_endpoints, vec![first, second]);
    assert_eq!(report.duplicate_candidates, 2);
    assert_eq!(report.stop, CellBep52DhtLookupStopV1::FrontierExhausted);
    assert_silent(&alias_socket);
}

#[test]
fn lookup_refuses_changed_advertised_node_id_and_keeps_wire_cost() {
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let peer = "127.0.0.1:6881".parse().unwrap();
    let first_server = serve(first_socket, [1; 20], vec![([2; 20], second)], vec![]);
    let second_server = serve(second_socket, [3; 20], vec![], vec![peer]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, second, peer]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    let bytes = first_server.join().unwrap() + second_server.join().unwrap();
    assert!(report.peer_candidates.is_empty());
    assert_eq!(report.successful_queries, 1);
    assert_eq!(session.usage().refused_dht_queries, 1);
    assert_eq!(session.usage().received_bytes, bytes as u64);
    assert_eq!(session.refusals()[0].0, SocketAddr::V4(second));
    assert!(session.refusals()[0]
        .1
        .contains("advertised node correlation"));
}

#[test]
fn lookup_continues_after_rejected_datagram_without_erasing_failure() {
    let (bad, bad_socket) = socket();
    let (good, good_socket) = socket();
    let peer = "127.0.0.1:6881".parse().unwrap();
    let bad_server = thread::spawn(move || {
        let (_, caller) = bad_socket.recv_from(&mut [0; 1200]).unwrap();
        bad_socket.send_to(&vec![b'x'; 16_384], caller).unwrap();
    });
    let good_server = serve(good_socket, [2; 20], vec![], vec![peer]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[bad, good, peer]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[bad, good],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    bad_server.join().unwrap();
    let valid_bytes = good_server.join().unwrap();
    assert_eq!(report.peer_candidates, vec![peer]);
    assert_eq!(report.successful_queries, 1);
    assert_eq!(
        session.usage().received_bytes,
        (16_384 + valid_bytes) as u64
    );
    assert_eq!(session.usage().refused_dht_queries, 1);
    assert_eq!(session.refusals().len(), 1);
}

#[test]
fn lookup_public_policy_refuses_private_and_special_destinations_before_io() {
    let policy = CellBep52DhtEndpointPolicyV1::public_ipv4();
    for ip in [
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.1",
        "100.127.255.254",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.0.0.9",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.168.1.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.19.255.254",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        assert!(
            !policy.admits(SocketAddrV4::new(ip.parse().unwrap(), 6881)),
            "{ip}"
        );
    }
    for ip in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.254",
        "100.128.0.1",
        "172.15.0.1",
        "172.32.0.1",
    ] {
        assert!(
            policy.admits(SocketAddrV4::new(ip.parse().unwrap(), 6881)),
            "{ip}"
        );
    }
    assert!(!policy.admits("1.1.1.1:0".parse().unwrap()));
    let (address, silent) = socket();
    let mut session = session();
    let before = session.usage().clone();
    assert!(lookup_cell_bep52_dht_peers(
        &binding(),
        &[address],
        [6; 20],
        &[[7; 8]],
        &policy,
        &mut session,
    )
    .is_err());
    assert_eq!(*session.usage(), before);
    assert_silent(&silent);
}

#[test]
fn lookup_limits_accumulated_peers_and_deduplicates_across_replies() {
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let peers: Vec<SocketAddrV4> = (1..=40)
        .map(|port| SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), port))
        .collect();
    let first_server = serve(
        first_socket,
        [1; 20],
        vec![([2; 20], second)],
        peers[..20].to_vec(),
    );
    let second_server = serve(second_socket, [2; 20], vec![], peers[10..].to_vec());
    let mut allowed = vec![first, second];
    allowed.extend(&peers);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&allowed).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    first_server.join().unwrap();
    second_server.join().unwrap();
    assert_eq!(report.peer_candidates, peers[..32]);
    assert_eq!(report.duplicate_candidates, 10);
    assert_eq!(report.stop, CellBep52DhtLookupStopV1::PeerLimit);
}

#[test]
fn lookup_inherits_previous_query_and_all_original_session_budgets() {
    let (first, first_socket) = socket();
    let (silent, silent_socket) = socket();
    let first_server = serve(first_socket, [1; 20], vec![], vec![]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, silent]).unwrap();
    let mut session = session();
    query_cell_bep52_dht_peers(&binding(), first, [6; 20], [7; 8], &mut session).unwrap();
    first_server.join().unwrap();
    let before = session.usage().clone();
    let original = session.limits;
    for limited in 0..4 {
        session.limits = original;
        match limited {
            0 => session.limits.max_connections = 1,
            1 => session.limits.max_received_bytes = session.usage.received_bytes + 65_535,
            2 => session.limits.max_sent_bytes = session.usage.sent_bytes,
            3 => {
                session.limits.max_messages =
                    session.usage.sent_messages + session.usage.received_messages + 1
            }
            _ => unreachable!(),
        }
        let report = lookup_cell_bep52_dht_peers(
            &binding(),
            &[silent],
            [6; 20],
            &[[8; 8]],
            &policy,
            &mut session,
        )
        .unwrap();
        assert_eq!(report.stop, CellBep52DhtLookupStopV1::SessionBudget);
        assert!(report.queried_endpoints.is_empty());
        assert_eq!(*session.usage(), before);
    }
    assert_silent(&silent_socket);
}

#[test]
fn lookup_refuses_transaction_reuse_and_invalid_input_before_io() {
    let (address, silent) = socket();
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[address]).unwrap();
    let mut session = session();
    session.dht_transactions.insert([9; 8]);
    for transactions in [
        vec![],
        vec![[0; 8]],
        vec![[7; 8], [7; 8]],
        vec![[9; 8]],
        vec![[7; 8]; 9],
    ] {
        assert!(lookup_cell_bep52_dht_peers(
            &binding(),
            &[address],
            [6; 20],
            &transactions,
            &policy,
            &mut session,
        )
        .is_err());
    }
    for bootstraps in [vec![], vec![address, address], vec![address; 9]] {
        assert!(lookup_cell_bep52_dht_peers(
            &binding(),
            &bootstraps,
            [6; 20],
            &[[7; 8]],
            &policy,
            &mut session,
        )
        .is_err());
    }
    assert!(CellBep52DhtEndpointPolicyV1::explicit(&[]).is_err());
    assert!(CellBep52DhtEndpointPolicyV1::explicit(&[address, address]).is_err());
    assert!(CellBep52DhtEndpointPolicyV1::explicit(&["127.0.0.1:0".parse().unwrap()]).is_err());
    assert_eq!(session.usage(), &CellBep52PeerUsageV1::default());
    assert_silent(&silent);
}

#[test]
fn lookup_cancellation_during_wait_latches_and_does_not_return_partial_success() {
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let first_server = serve(first_socket, [1; 20], vec![([2; 20], second)], vec![]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, second]).unwrap();
    let mut session = session();
    let cancelled = session.cancellation_handle();
    let cancel_handle = Arc::clone(&cancelled);
    let second_server = thread::spawn(move || {
        second_socket.recv_from(&mut [0; 1200]).unwrap();
        cancel_handle.store(true, Ordering::Release);
    });
    let error = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap_err();
    first_server.join().unwrap();
    second_server.join().unwrap();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(session.usage().dht_query_attempts, 2);
    assert_eq!(session.usage().refused_dht_queries, 1);
    let before = session.usage().clone();
    cancelled.store(false, Ordering::Release);
    assert!(lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[9; 8]],
        &policy,
        &mut session,
    )
    .is_err());
    assert_eq!(*session.usage(), before);
}

#[test]
fn lookup_late_second_hop_cannot_extend_original_deadline() {
    let (first, first_socket) = socket();
    let (second, second_socket) = socket();
    let first_server = serve(first_socket, [1; 20], vec![([2; 20], second)], vec![]);
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[first, second]).unwrap();
    let mut session = session();
    session.limits.deadline = Instant::now() + Duration::from_secs(1);
    session.limits.request_timeout = Duration::from_secs(2);
    let original_deadline = session.deadline();
    let second_server = thread::spawn(move || {
        let mut query = [0; 1200];
        let (count, caller) = second_socket.recv_from(&mut query).unwrap();
        let (value, _) = decode(&query[..count]).unwrap();
        let transaction = value
            .field(b"t")
            .unwrap()
            .bytes()
            .unwrap()
            .try_into()
            .unwrap();
        thread::sleep(
            original_deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(30),
        );
        second_socket
            .send_to(&response(transaction, [2; 20], &[], &[]), caller)
            .unwrap();
    });
    let error = lookup_cell_bep52_dht_peers(
        &binding(),
        &[first],
        [6; 20],
        &[[7; 8], [8; 8]],
        &policy,
        &mut session,
    )
    .unwrap_err();
    first_server.join().unwrap();
    second_server.join().unwrap();
    assert!(error.to_string().contains("deadline"));
    assert_eq!(session.deadline(), original_deadline);
    assert_eq!(session.usage().dht_query_attempts, 2);
    assert_eq!(session.usage().refused_dht_queries, 1);
}

#[test]
fn lookup_ipv4_profile_cannot_smuggle_mapped_ipv6_compact_peers() {
    let (address, server_socket) = socket();
    let server = thread::spawn(move || {
        let (_, caller) = server_socket.recv_from(&mut [0; 1200]).unwrap();
        let mut bytes = b"d1:rd2:id20:012345678901234567895:token1:t6:valuesl18:".to_vec();
        bytes.extend([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 0x1a, 0xe1,
        ]);
        bytes.extend(b"ee1:t8:");
        bytes.extend([7; 8]);
        bytes.extend(b"1:y1:re");
        server_socket.send_to(&bytes, caller).unwrap();
        bytes.len()
    });
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&[address]).unwrap();
    let mut session = session();
    let report = lookup_cell_bep52_dht_peers(
        &binding(),
        &[address],
        [6; 20],
        &[[7; 8]],
        &policy,
        &mut session,
    )
    .unwrap();
    let received = server.join().unwrap();
    assert_eq!(report.successful_queries, 0);
    assert!(report.peer_candidates.is_empty());
    assert_eq!(session.usage().received_bytes, received as u64);
    assert_eq!(session.usage().refused_dht_queries, 1);
}
