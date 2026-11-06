//! A separately selected, fresh owner. This does not upgrade an existing PNQ2
//! ledger, enable public ingress or qualify private tasks/production service.
use super::*;
use trnm_protocol::pq_legacy_profile::RESPONSE_BYTES_DOMAIN;

pub const TLS_PROFILE: &str = "native-pq-network-tls13-owner-v1";
pub const TLS_TRANSPORT_MODE: &str = "loopback-tls13-x25519mlkem768-mldsa65-v1";
// Handshake attempts, not a count/bound on OpenSSL's certificate verifications
// or CPU. This fresh owner is deliberately tighter than the original 64 TCP
// connections. No failure or cold reopen refunds an admitted attempt.
pub const TLS_HANDSHAKE_LIMIT: u64 = 16;
const TLS_POLICY_DOMAIN: &[u8] = b"native-pq-network-tls13-policy-v1";
const TLS_CONTEXT_DOMAIN: &[u8] = b"native-pq-network-tls13-peer-context-v1";
const TLS_OPERATION_DOMAIN: &[u8] = b"native-pq-network-tls13-operation-v1";
const TLS_RESPONSE_DOMAIN: &[u8] = b"native-pq-network-tls13-response-bytes-v1";

/// External configuration inputs. The CA certificate is pinned by its exact DER
/// SHA-256, independently of the live peer's strict ML-DSA SPKI roster entry.
/// A local test CA is not evidence of independent production key custody.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PqTlsPins {
    ca_certificate_sha256: Hash,
    server_name: String,
}

impl PqTlsPins {
    pub fn new(ca_certificate_sha256: Hash, server_name: String) -> Result<Self> {
        let pins = Self {
            ca_certificate_sha256,
            server_name,
        };
        pins.validate()?;
        Ok(pins)
    }

    fn validate(&self) -> Result<()> {
        ensure(self.ca_certificate_sha256 != [0; 32], "PQ_TLS_CA_PIN")?;
        ensure(
            !self.server_name.is_empty()
                && self.server_name.len() <= 253
                && self.server_name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                }),
            "PQ_TLS_SERVER_NAME",
        )
    }

    pub fn ca_certificate_sha256(&self) -> Hash {
        self.ca_certificate_sha256
    }
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

impl PolicyRecord {
    pub(super) fn validate_transport(&self) -> Result<()> {
        match &self.tls {
            None => ensure(
                self.schema == PROFILE && self.transport_confidentiality == TRANSPORT_MODE,
                "PQ_NETWORK_POLICY_RECORD",
            ),
            Some(pins) => {
                ensure(
                    self.schema == TLS_PROFILE
                        && self.transport_confidentiality == TLS_TRANSPORT_MODE
                        && self.ingress_connection_limit == TLS_HANDSHAKE_LIMIT,
                    "PQ_NETWORK_POLICY_RECORD",
                )?;
                pins.validate()
            }
        }
    }
}

impl PqNetworkPolicy {
    /// This profile requires a fresh policy namespace: open/reopen checks the
    /// whole canonical policy in the actual durable Node owner. It cannot reuse
    /// a plaintext owner's store, operation IDs, signatures or cached receipts.
    pub fn new_tls13(
        settings: &Settings,
        server_spki: &[u8],
        generation: u64,
        peer_spkis: impl IntoIterator<Item = Vec<u8>>,
        pins: PqTlsPins,
    ) -> Result<Self> {
        pins.validate()?;
        let mut policy = Self::new(settings, server_spki, generation, peer_spkis)?;
        policy.record.schema = TLS_PROFILE.into();
        policy.record.transport_confidentiality = TLS_TRANSPORT_MODE.into();
        policy.record.ingress_connection_limit = TLS_HANDSHAKE_LIMIT;
        policy.record.tls = Some(pins);
        policy.bytes = serde_json::to_vec(&policy.record)?;
        policy.id = hash(TLS_POLICY_DOMAIN, &[&policy.bytes]);
        Ok(policy)
    }

    pub fn transport_requires_tls(&self) -> bool {
        self.record.tls.is_some()
    }
    pub fn profile(&self) -> &str {
        &self.record.schema
    }
    pub(crate) fn ingress_connection_limit(&self) -> u64 {
        if self.transport_requires_tls() {
            TLS_HANDSHAKE_LIMIT
        } else {
            MAX_INGRESS_CONNECTIONS
        }
    }
    pub(super) fn require_plaintext(&self) -> Result<()> {
        ensure(!self.transport_requires_tls(), "PQ_TLS_REQUIRED")
    }
    pub fn tls_pins(&self) -> Result<&PqTlsPins> {
        self.record
            .tls
            .as_ref()
            .ok_or_else(|| "PQ_TLS_POLICY_REQUIRED".into())
    }
    pub(super) fn request_magic(&self) -> &'static [u8; 4] {
        if self.transport_requires_tls() {
            b"PQT1"
        } else {
            REQUEST_MAGIC
        }
    }
    pub(super) fn response_magic(&self) -> &'static [u8; 4] {
        if self.transport_requires_tls() {
            b"PQS1"
        } else {
            RESPONSE_MAGIC
        }
    }
    pub(super) fn response_schema(&self) -> &'static str {
        if self.transport_requires_tls() {
            "native-pq-network-tls13-response-v1"
        } else {
            RESPONSE_SCHEMA
        }
    }
    pub(super) fn context_domain(&self) -> &'static [u8] {
        if self.transport_requires_tls() {
            TLS_CONTEXT_DOMAIN
        } else {
            PEER_CONTEXT_DOMAIN
        }
    }
    pub(super) fn operation_domain(&self) -> &'static [u8] {
        if self.transport_requires_tls() {
            TLS_OPERATION_DOMAIN
        } else {
            OPERATION_DOMAIN
        }
    }
    pub(crate) fn response_digest(&self, response: &[u8]) -> Hash {
        hash(
            if self.transport_requires_tls() {
                TLS_RESPONSE_DOMAIN
            } else {
                RESPONSE_BYTES_DOMAIN
            },
            &[response],
        )
    }
}
