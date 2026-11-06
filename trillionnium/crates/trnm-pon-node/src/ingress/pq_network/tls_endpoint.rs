//! Explicit fixed-endpoint development transport. Address pins restrict routing;
//! they never replace the existing TLS/SPKI, PNQ signature or witness authority.
use super::*;
use std::net::{IpAddr, Ipv4Addr};

pub const TLS_ENDPOINT_PROFILE: &str = "native-pq-network-tls13-endpoint-owner-v1";
pub const TLS_ENDPOINT_TRANSPORT_MODE: &str = "pinned-endpoint-tls13-x25519mlkem768-mldsa65-v1";
// A finite local service allowance, including rejected source IPs. This is not
// a restart-persistent budget or a claim of public denial-of-service resistance.
pub const TLS_ENDPOINT_ACCEPT_LIMIT: u64 = 64;
pub(super) const POLICY_DOMAIN: &[u8] = b"native-pq-network-tls13-endpoint-policy-v1";
pub(super) const CONTEXT_DOMAIN: &[u8] = b"native-pq-network-tls13-endpoint-peer-context-v1";
pub(super) const OPERATION_DOMAIN: &[u8] = b"native-pq-network-tls13-endpoint-operation-v1";
pub(super) const RESPONSE_DOMAIN: &[u8] = b"native-pq-network-tls13-endpoint-response-bytes-v1";

/// Immutable IPv4 endpoint and source-address pins for a bounded development
/// run. Loopback is permitted for tests. Wildcards, port zero, IPv6 aliases and
/// discovery/NAT substitution are not part of this explicit profile.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PqTlsEndpointPins {
    server_address: SocketAddr,
    allowed_client_ips: Vec<IpAddr>,
}

fn allowed_ipv4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip != Ipv4Addr::UNSPECIFIED && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(_) => false,
    }
}

impl PqTlsEndpointPins {
    pub fn new(server_address: SocketAddr, mut allowed_client_ips: Vec<IpAddr>) -> Result<Self> {
        ensure(
            (1..=MAX_PEERS).contains(&allowed_client_ips.len()),
            "PQ_TLS_ENDPOINT_CLIENTS",
        )?;
        allowed_client_ips.sort_unstable();
        let pins = Self {
            server_address,
            allowed_client_ips,
        };
        pins.validate()?;
        Ok(pins)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure(
            allowed_ipv4(self.server_address.ip()) && self.server_address.port() != 0,
            "PQ_TLS_ENDPOINT_ADDRESS",
        )?;
        ensure(
            (1..=MAX_PEERS).contains(&self.allowed_client_ips.len())
                && self.allowed_client_ips.iter().all(|ip| allowed_ipv4(*ip))
                && self
                    .allowed_client_ips
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            "PQ_TLS_ENDPOINT_CLIENTS",
        )
    }

    pub fn server_address(&self) -> SocketAddr {
        self.server_address
    }

    pub fn allowed_client_ips(&self) -> &[IpAddr] {
        &self.allowed_client_ips
    }
}

impl PqNetworkPolicy {
    /// Select a new signed/stored namespace with mandatory PNQ2 witness use.
    /// This never widens an existing loopback policy or enrolls a witness.
    pub fn new_tls13_endpoint(
        settings: &Settings,
        server_spki: &[u8],
        generation: u64,
        peer_spkis: impl IntoIterator<Item = Vec<u8>>,
        pins: PqTlsPins,
        endpoint: PqTlsEndpointPins,
    ) -> Result<Self> {
        endpoint.validate()?;
        let mut policy = Self::new_tls13(settings, server_spki, generation, peer_spkis, pins)?;
        policy.record.schema = TLS_ENDPOINT_PROFILE.into();
        policy.record.transport_confidentiality = TLS_ENDPOINT_TRANSPORT_MODE.into();
        policy.record.endpoint = Some(endpoint);
        policy.bytes = serde_json::to_vec(&policy.record)?;
        policy.id = hash(POLICY_DOMAIN, &[&policy.bytes]);
        Ok(policy)
    }

    pub fn tls_endpoint_pins(&self) -> Option<&PqTlsEndpointPins> {
        self.record.endpoint.as_ref()
    }

    /// Also used before ordinary CLI owner creation. The actual library
    /// listener rechecks its kernel-reported local address before serving.
    pub fn check_tls_listener(&self, address: SocketAddr) -> Result<()> {
        self.tls_pins()?;
        self.check_network_target(address)
    }

    pub(super) fn check_network_target(&self, address: SocketAddr) -> Result<()> {
        match self.tls_endpoint_pins() {
            Some(pins) => ensure(address == pins.server_address, "PQ_TLS_ENDPOINT_TARGET"),
            None => ensure(address.ip().is_loopback(), "PQ_NETWORK_LOOPBACK_ONLY"),
        }
    }

    pub(super) fn check_tls_client_ip(&self, address: SocketAddr) -> Result<()> {
        match self.tls_endpoint_pins() {
            Some(pins) => ensure(
                pins.allowed_client_ips.binary_search(&address.ip()).is_ok(),
                "PQ_TLS_ENDPOINT_CLIENT_IP",
            ),
            None => Ok(()),
        }
    }
}

pub(crate) fn policy_record_requires_endpoint_witness(bytes: &[u8]) -> Result<bool> {
    let record: PolicyRecord = serde_json::from_slice(bytes)?;
    ensure(
        serde_json::to_vec(&record)? == bytes,
        "PQ_NETWORK_POLICY_RECORD",
    )?;
    record.validate_transport()?;
    Ok(record.endpoint.is_some())
}
