//! One-hop, caller-directed BEP5 get_peers with BEP43 read-only signalling.
//! Returns unauthenticated hints only. It neither follows nodes nor announces.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use super::*;

pub const MAX_CELL_BEP52_DHT_RESPONSE_BYTES_V1: usize = 1_200;
// A full IPv4 UDP payload fits, even when it violates the admitted 1200-byte
// message profile. Reserving this before the query lets us count a rejected
// datagram's complete application payload without truncation or overshoot.
const DATAGRAM_RECEIVE_RESERVATION: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52DhtNodeHintV1 {
    pub node_id: [u8; 20],
    pub endpoint: SocketAddrV4,
}

/// These addresses and node IDs are untrusted advertisements. `info_hash` is
/// the caller's original binding, not a fact authenticated by a DHT response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52DhtHintsV1 {
    pub operation_id: CellDigestV1,
    pub info_hash: CellDigestV1,
    pub queried_endpoint: SocketAddrV4,
    pub response_node_id: [u8; 20],
    pub peer_candidates: Vec<SocketAddrV4>,
    pub closer_node_candidates: Vec<CellBep52DhtNodeHintV1>,
}

/// Query exactly one independently caller-approved IPv4 endpoint. The caller
/// supplies a fresh eight-byte correlation ID and local node ID. Query IDs may
/// not be reused within this session. The returned token is deliberately not
/// exposed: this API cannot announce a provider or become a public DHT node.
///
/// At most eight TCP connections plus UDP queries share the session's original
/// deadline and byte/message allowance. No automatic traversal or retry occurs.
/// A lookup exposes the truncated content identifier to that queried endpoint.
pub fn query_cell_bep52_dht_peers(
    binding: &CellBep52BindingV1,
    bootstrap: SocketAddrV4,
    node_id: [u8; 20],
    transaction_id: [u8; 8],
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52DhtHintsV1> {
    valid_endpoint(bootstrap)?;
    session.check(session.limits.deadline)?;
    require(
        transaction_id != [0; 8] && !session.dht_transactions.contains(&transaction_id),
        "BEP52 DHT transaction reuse",
    )?;
    require(
        session.usage.connection_attempts + session.usage.dht_query_attempts
            < session.limits.max_connections,
        "BEP52 connection budget",
    )?;
    require(
        session.usage.received_messages + session.usage.sent_messages + 2
            <= session.limits.max_messages,
        "BEP52 message budget",
    )?;
    require(
        session.limits.max_received_bytes - session.usage.received_bytes
            >= DATAGRAM_RECEIVE_RESERVATION as u64,
        "BEP52 DHT complete datagram reservation",
    )?;
    let query = query_bytes(binding, node_id, transaction_id);
    require(
        query.len() as u64 <= session.limits.max_sent_bytes - session.usage.sent_bytes,
        "BEP52 send byte budget",
    )?;
    let deadline = session.request_deadline()?;
    session.usage.dht_query_attempts += 1;
    session.dht_transactions.insert(transaction_id);
    let result = query_inner(
        binding,
        bootstrap,
        transaction_id,
        &query,
        deadline,
        session,
    );
    if let Err(error) = &result {
        session.usage.refused_dht_queries += 1;
        session.refusals.push((
            bootstrap.into(),
            error.to_string().chars().take(256).collect(),
        ));
    }
    result
}

fn query_bytes(binding: &CellBep52BindingV1, node_id: [u8; 20], transaction: [u8; 8]) -> Vec<u8> {
    let mut bytes = b"d1:ad2:id20:".to_vec();
    bytes.extend_from_slice(&node_id);
    bytes.extend_from_slice(b"9:info_hash20:");
    bytes.extend_from_slice(&binding.info_hash()[..20]);
    bytes.extend_from_slice(b"e1:q9:get_peers2:roi1e1:t8:");
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(b"1:y1:qe");
    bytes
}

fn query_inner(
    binding: &CellBep52BindingV1,
    bootstrap: SocketAddrV4,
    transaction: [u8; 8],
    query: &[u8],
    deadline: Instant,
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52DhtHintsV1> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(bootstrap)?;
    session.check(deadline)?;
    socket.set_write_timeout(Some(
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_micros(1)),
    ))?;
    session.frame(true)?;
    let count = socket.send(query)?;
    session.usage.sent_bytes += count as u64;
    require(count == query.len(), "BEP52 DHT partial query")?;
    session.frame(false)?;
    let mut bytes = vec![0; DATAGRAM_RECEIVE_RESERVATION];
    let count = loop {
        session.check(deadline)?;
        socket.set_read_timeout(Some(
            IO_POLL
                .min(deadline.saturating_duration_since(Instant::now()))
                .max(Duration::from_micros(1)),
        ))?;
        match socket.recv_from(&mut bytes) {
            Ok((count, source)) => {
                session.usage.received_bytes += count as u64;
                require(
                    source == SocketAddr::V4(bootstrap),
                    "BEP52 DHT source correlation",
                )?;
                break count;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
    };
    session.check(deadline)?;
    require(
        count <= MAX_CELL_BEP52_DHT_RESPONSE_BYTES_V1,
        "BEP52 DHT response size",
    )?;
    let hints = parse_response(
        &bytes[..count],
        binding,
        bootstrap,
        transaction,
        session.operation_id,
    )?;
    session.check(deadline)?;
    Ok(hints)
}

fn valid_endpoint(endpoint: SocketAddrV4) -> CellResultV1<()> {
    require(
        endpoint.port() != 0
            && !endpoint.ip().is_unspecified()
            && !endpoint.ip().is_multicast()
            && !endpoint.ip().is_broadcast(),
        "BEP52 DHT endpoint",
    )
}

fn compact_endpoint(bytes: &[u8]) -> CellResultV1<SocketAddrV4> {
    require(bytes.len() == 6, "BEP52 DHT compact peer length")?;
    let endpoint = SocketAddrV4::new(
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
    );
    valid_endpoint(endpoint)?;
    Ok(endpoint)
}

fn parse_response(
    bytes: &[u8],
    binding: &CellBep52BindingV1,
    bootstrap: SocketAddrV4,
    transaction: [u8; 8],
    operation_id: CellDigestV1,
) -> CellResultV1<CellBep52DhtHintsV1> {
    let (value, used) = decode(bytes)?;
    require(used == bytes.len(), "BEP52 DHT trailing bytes")?;
    require(
        value.field(b"t")?.bytes()? == transaction,
        "BEP52 DHT transaction correlation",
    )?;
    require(
        value.field(b"y")?.bytes()? == b"r",
        "BEP52 DHT response required",
    )?;
    let response = value.field(b"r")?;
    let response_id = response.field(b"id")?.bytes()?;
    require(response_id.len() == 20, "BEP52 DHT node identity length")?;
    let token = response.field(b"token")?.bytes()?;
    require((1..=64).contains(&token.len()), "BEP52 DHT token bound")?;
    let mut peers = Vec::new();
    let mut nodes = Vec::new();
    let values = response.optional(b"values")?;
    let contacts = response.optional(b"nodes")?;
    require(
        values.is_some() || contacts.is_some(),
        "BEP52 DHT candidates missing",
    )?;
    if let Some(values) = values {
        let values = values.list()?;
        require(values.len() <= 32, "BEP52 DHT peer count")?;
        let mut seen = BTreeSet::new();
        for value in values {
            let endpoint = compact_endpoint(value.bytes()?)?;
            require(seen.insert(endpoint), "BEP52 DHT duplicate peer")?;
            peers.push(endpoint);
        }
    }
    if let Some(contacts) = contacts {
        let contacts = contacts.bytes()?;
        require(
            contacts.len().is_multiple_of(26) && contacts.len() <= 8 * 26,
            "BEP52 DHT compact node bound",
        )?;
        let mut identifiers = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for contact in contacts.chunks_exact(26) {
            let id: [u8; 20] = contact[..20].try_into().unwrap();
            let endpoint = compact_endpoint(&contact[20..])?;
            require(
                identifiers.insert(id) && endpoints.insert(endpoint),
                "BEP52 DHT duplicate node",
            )?;
            nodes.push(CellBep52DhtNodeHintV1 {
                node_id: id,
                endpoint,
            });
        }
    }
    Ok(CellBep52DhtHintsV1 {
        operation_id,
        info_hash: binding.info_hash(),
        queried_endpoint: bootstrap,
        response_node_id: response_id.try_into().unwrap(),
        peer_candidates: peers,
        closer_node_candidates: nodes,
    })
}

#[cfg(test)]
mod tests;
