//! Opt-in bounded IPv4 BEP5 lookup. This is a query client, not a DHT server.
//!
//! BEP5 XOR distance orders admitted node advertisements. BEP43 `ro=1`, the
//! original socket/accounting owner and the 1200-byte response profile remain.
//! No routing table is persisted, no announce is sent, and no peer is dialled.
//! BEP32 IPv6/mixed-family contacts are outside this IPv4-only wire profile.

use super::*;

const MAX_LOOKUP_QUERIES: usize = 8;
const MAX_LOOKUP_PEERS: usize = 32;
const MAX_EXPLICIT_ENDPOINTS: usize = 64;

/// Immutable network scope for one lookup. It grants no peer identity, custody,
/// content permission or model-use authority. Public addresses are still hints.
/// The explicit mode is useful for private networks and controlled experiments;
/// addresses learned from a reply cannot extend its exact endpoint allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52DhtEndpointPolicyV1 {
    public_ipv4: bool,
    explicit: BTreeSet<SocketAddrV4>,
}

impl CellBep52DhtEndpointPolicyV1 {
    /// Conservative public IPv4 unicast scope. Special-purpose ranges,
    /// multicast and reserved destinations are excluded. This is a fixed
    /// policy, not a routability, ownership or independent-operator claim.
    pub fn public_ipv4() -> Self {
        Self {
            public_ipv4: true,
            explicit: BTreeSet::new(),
        }
    }

    /// Admit exactly these 1..=64 IPv4 endpoints (including their ports).
    /// IPv6, including IPv4-mapped IPv6, is not representable by this API.
    pub fn explicit(endpoints: &[SocketAddrV4]) -> CellResultV1<Self> {
        require(
            (1..=MAX_EXPLICIT_ENDPOINTS).contains(&endpoints.len()),
            "BEP52 DHT explicit endpoint bound",
        )?;
        let explicit: BTreeSet<_> = endpoints.iter().copied().collect();
        require(
            explicit.len() == endpoints.len(),
            "BEP52 DHT explicit endpoint duplicate",
        )?;
        for endpoint in endpoints {
            valid_endpoint(*endpoint)?;
        }
        Ok(Self {
            public_ipv4: false,
            explicit,
        })
    }

    fn admits(&self, endpoint: SocketAddrV4) -> bool {
        valid_endpoint(endpoint).is_ok()
            && if self.public_ipv4 {
                public_unicast(*endpoint.ip())
            } else {
                self.explicit.contains(&endpoint)
            }
    }
}

// Deliberately exclude the complete IANA special-purpose blocks, including
// their narrow globally reachable service exceptions. No DNS resolution or
// implicit IPv6 conversion can turn a permitted literal into a local address.
fn public_unicast(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(matches!(a, 0 | 10 | 127 | 224..=255)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192
            && ((b == 0 && matches!(c, 0 | 2))
                || (b == 31 && c == 196)
                || (b == 52 && c == 193)
                || (b == 88 && c == 99)
                || b == 168
                || (b == 175 && c == 48)))
        || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

/// The bounded client stopped; none of these reasons establishes DHT coverage
/// or peer availability. Expiry and cancellation return an error, not a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellBep52DhtLookupStopV1 {
    FrontierExhausted,
    PeerLimit,
    QueryLimit,
    SessionBudget,
}

/// Unauthenticated hints from a completed bounded observation. Queried
/// endpoints include failed requests; the original session retains their
/// actual socket usage and capped refusal descriptions on both success/error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellBep52DhtLookupReportV1 {
    pub operation_id: CellDigestV1,
    pub info_hash: CellDigestV1,
    pub queried_endpoints: Vec<SocketAddrV4>,
    pub successful_queries: usize,
    pub rejected_candidates: usize,
    pub duplicate_candidates: usize,
    pub peer_candidates: Vec<SocketAddrV4>,
    pub stop: CellBep52DhtLookupStopV1,
}

#[derive(Clone, Copy)]
struct Candidate {
    endpoint: SocketAddrV4,
    expected_id: Option<[u8; 20]>,
}

/// Follow admitted `nodes` advertisements under the existing session. The
/// caller supplies 1..=8 fresh, unpredictable, nonzero transaction IDs; each
/// may be consumed once. Distinct bootstrap endpoints are checked against the
/// policy before any socket is opened. Bootstrap queries precede discovered
/// nodes; discovered nodes are ordered by XOR distance to the truncated hash.
///
/// All UDP and TCP attempts share the session's original at-most-eight attempt
/// limit, absolute deadline, cancellation latch and byte/message counters.
/// There is no retry or replenishment. At most 8 bootstrap + 8*8 advertised
/// node endpoints and 32 peer endpoints are retained. Node IDs and endpoints
/// are deduplicated, and a queried advertisement must return the same node ID.
/// That correlation is not authentication or resistance to Sybil/eclipse
/// attacks. Each admitted query discloses the truncated content identifier to
/// that endpoint. Even a returned peer requires independent content validation.
pub fn lookup_cell_bep52_dht_peers(
    binding: &CellBep52BindingV1,
    bootstraps: &[SocketAddrV4],
    node_id: [u8; 20],
    transaction_ids: &[[u8; 8]],
    policy: &CellBep52DhtEndpointPolicyV1,
    session: &mut CellBep52PeerSessionV1,
) -> CellResultV1<CellBep52DhtLookupReportV1> {
    session.check(session.limits.deadline)?;
    require(
        (1..=MAX_LOOKUP_QUERIES).contains(&bootstraps.len())
            && (1..=MAX_LOOKUP_QUERIES).contains(&transaction_ids.len()),
        "BEP52 DHT lookup input bound",
    )?;
    let mut seen_endpoints: BTreeSet<_> = bootstraps.iter().copied().collect();
    require(
        seen_endpoints.len() == bootstraps.len()
            && bootstraps.iter().all(|endpoint| policy.admits(*endpoint)),
        "BEP52 DHT bootstrap policy/duplicate",
    )?;
    let mut transactions = BTreeSet::new();
    require(
        transaction_ids.iter().all(|id| {
            *id != [0; 8] && !session.dht_transactions.contains(id) && transactions.insert(*id)
        }),
        "BEP52 DHT transaction reuse",
    )?;
    let mut frontier: Vec<_> = bootstraps
        .iter()
        .map(|endpoint| Candidate {
            endpoint: *endpoint,
            expected_id: None,
        })
        .collect();
    let mut seen_ids = BTreeSet::from([node_id]);
    let mut peers = BTreeSet::new();
    let mut report = CellBep52DhtLookupReportV1 {
        operation_id: session.operation_id,
        info_hash: binding.info_hash(),
        queried_endpoints: Vec::new(),
        successful_queries: 0,
        rejected_candidates: 0,
        duplicate_candidates: 0,
        peer_candidates: Vec::new(),
        stop: CellBep52DhtLookupStopV1::FrontierExhausted,
    };
    loop {
        session.check(session.limits.deadline)?;
        if peers.len() == MAX_LOOKUP_PEERS {
            report.stop = CellBep52DhtLookupStopV1::PeerLimit;
            break;
        }
        if frontier.is_empty() {
            break;
        }
        let Some(&transaction) = transaction_ids.get(report.queried_endpoints.len()) else {
            report.stop = CellBep52DhtLookupStopV1::QueryLimit;
            break;
        };
        let query_size = query_bytes(binding, node_id, transaction).len() as u64;
        if !query_fits(session, query_size) {
            report.stop = CellBep52DhtLookupStopV1::SessionBudget;
            break;
        }
        let next = frontier
            .iter()
            .enumerate()
            .min_by_key(|(_, candidate)| {
                (
                    candidate.expected_id.is_some(),
                    candidate
                        .expected_id
                        .map(|id| xor_distance(id, binding.info_hash()))
                        .unwrap_or([0; 20]),
                    candidate.endpoint,
                )
            })
            .map(|(index, _)| index)
            .unwrap();
        let candidate = frontier.remove(next);
        report.queried_endpoints.push(candidate.endpoint);
        let hints =
            query_cell_bep52_dht_peers(binding, candidate.endpoint, node_id, transaction, session);
        // A successful earlier hop never turns expiry/cancellation into a
        // successful partial result; their original errors remain visible.
        session.check(session.limits.deadline)?;
        let Ok(hints) = hints else { continue };
        if candidate
            .expected_id
            .is_some_and(|expected| expected != hints.response_node_id)
        {
            session.usage.refused_dht_queries += 1;
            session.refusals.push((
                candidate.endpoint.into(),
                "BEP52 DHT advertised node correlation".into(),
            ));
            continue;
        }
        report.successful_queries += 1;
        seen_ids.insert(hints.response_node_id);
        for endpoint in hints.peer_candidates {
            if !policy.admits(endpoint) {
                report.rejected_candidates += 1;
            } else if peers.contains(&endpoint) {
                report.duplicate_candidates += 1;
            } else if peers.len() < MAX_LOOKUP_PEERS {
                peers.insert(endpoint);
            }
        }
        for hint in hints.closer_node_candidates {
            if !policy.admits(hint.endpoint) {
                report.rejected_candidates += 1;
                continue;
            }
            if seen_endpoints.contains(&hint.endpoint) || seen_ids.contains(&hint.node_id) {
                report.duplicate_candidates += 1;
                continue;
            }
            seen_endpoints.insert(hint.endpoint);
            seen_ids.insert(hint.node_id);
            frontier.push(Candidate {
                endpoint: hint.endpoint,
                expected_id: Some(hint.node_id),
            });
        }
    }
    session.check(session.limits.deadline)?;
    report.peer_candidates = peers.into_iter().collect();
    Ok(report)
}

fn xor_distance(id: [u8; 20], info_hash: CellDigestV1) -> [u8; 20] {
    std::array::from_fn(|index| id[index] ^ info_hash[index])
}

fn query_fits(session: &CellBep52PeerSessionV1, query_size: u64) -> bool {
    session.usage.connection_attempts + session.usage.dht_query_attempts
        < session.limits.max_connections
        && session.usage.received_messages + session.usage.sent_messages + 2
            <= session.limits.max_messages
        && session.limits.max_received_bytes - session.usage.received_bytes
            >= DATAGRAM_RECEIVE_RESERVATION as u64
        && query_size <= session.limits.max_sent_bytes - session.usage.sent_bytes
}

#[cfg(test)]
mod tests;
