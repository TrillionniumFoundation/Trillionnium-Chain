//! Explicit fresh PQ-only native network owner. This authenticates transport,
//! never account spending, task signatures, PoN work or model-install authority.
//! The loopback-only profile retains a bounded durable replay ledger. It has no
//! confidentiality, public saturation, account migration or WAN qualification.
use super::{Request, WorkCheckedPacket};
use crate::{ensure, Error, ErrorCode, Node, Result, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::{
    pon_wire::{hash, Hash},
    pq_frame::{
        ml_dsa_65_key_id_from_spki, payload_commitment, PqFrameExpectation, TPQ1_SIGNED_BYTES,
        TPQ1_UNSIGNED_BYTES,
    },
};

pub const PROFILE: &str = "native-pq-network-owner-v2";
pub(crate) const MAX_WIRE: usize = 2 * 1024 * 1024;
pub(crate) const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_RECORDS: u64 = 4096;
pub(crate) const MAX_INGRESS_CONNECTIONS: u64 = 64;
pub(crate) const MAX_INGRESS_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_INBOUND_VERIFICATIONS: u64 = 64;
const MAX_LIFETIME_SECONDS: u64 = 60;
const REQUEST_MAGIC: &[u8; 4] = b"PNQ2";
const RESPONSE_MAGIC: &[u8; 4] = b"PNP2";
// TPQ1 purpose 6 is the existing peer-authorization purpose. Directions are
// separate owner contexts; transaction/artifact purpose assignments stay intact.
const PEER_PURPOSE: u8 = 6;
#[derive(Clone, Copy)]
enum Direction {
    Request = 1,
    Response = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    schema: String,
    network: String,
    parameters: String,
    genesis: String,
    server_spki: String,
    generation: u64,
    peers: Vec<String>,
    ledger_byte_limit: u64,
    ledger_record_limit: u64,
    ingress_connection_limit: u64,
    ingress_byte_limit: u64,
    inbound_verification_limit: u64,
    transport_confidentiality: String,
}

/// Operator-supplied pins. No key from an incoming frame can enter this roster.
pub struct PqNetworkPolicy {
    record: PolicyRecord,
    bytes: Vec<u8>,
    id: Hash,
    network: Hash,
    server_id: Hash,
    server: PqNativeVerifier,
    peers: BTreeMap<Hash, PqNativeVerifier>,
}

fn crypto(error: impl std::fmt::Debug) -> Error {
    Error::from(format!("PQ_NETWORK_CRYPTO:{error:?}"))
}

impl PqNetworkPolicy {
    pub fn new(
        settings: &Settings,
        server_spki: &[u8],
        generation: u64,
        peer_spkis: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self> {
        ensure(
            (1..=i64::MAX as u64).contains(&generation),
            "PQ_NETWORK_GENERATION",
        )?;
        let server_id = ml_dsa_65_key_id_from_spki(server_spki).map_err(crypto)?;
        let server = PqNativeVerifier::from_pinned_spki(server_spki, server_id).map_err(crypto)?;
        let mut peers = BTreeMap::new();
        let mut public = BTreeMap::new();
        for spki in peer_spkis {
            ensure(peers.len() < 64, "PQ_NETWORK_PEER_LIMIT")?;
            let id = ml_dsa_65_key_id_from_spki(&spki).map_err(crypto)?;
            ensure(
                id != server_id && !peers.contains_key(&id),
                "PQ_NETWORK_DUPLICATE_KEY",
            )?;
            peers.insert(
                id,
                PqNativeVerifier::from_pinned_spki(&spki, id).map_err(crypto)?,
            );
            public.insert(id, hex::encode(spki));
        }
        ensure(!peers.is_empty(), "PQ_NETWORK_PEER_LIMIT")?;
        let record = PolicyRecord {
            schema: PROFILE.into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            server_spki: hex::encode(server_spki),
            generation,
            peers: public.into_values().collect(),
            ledger_byte_limit: MAX_LEDGER_BYTES,
            ledger_record_limit: MAX_RECORDS,
            ingress_connection_limit: MAX_INGRESS_CONNECTIONS,
            ingress_byte_limit: MAX_INGRESS_BYTES,
            inbound_verification_limit: MAX_INBOUND_VERIFICATIONS,
            transport_confidentiality: "loopback-signed-plaintext-dev-only".into(),
        };
        let bytes = serde_json::to_vec(&record)?;
        let id = hash(b"native-pq-network-policy-v2", &[&bytes]);
        Ok(Self {
            record,
            bytes,
            id,
            network: settings.network(),
            server_id,
            server,
            peers,
        })
    }

    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn server_key_id(&self) -> Hash {
        self.server_id
    }
    pub fn generation(&self) -> u64 {
        self.record.generation
    }
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn peer_ids(&self) -> impl Iterator<Item = Hash> + '_ {
        self.peers.keys().copied()
    }
    pub(crate) fn matches(&self, settings: &Settings) -> bool {
        self.network == settings.network()
            && self.record.parameters == hex::encode(settings.parameters())
            && self.record.genesis == hex::encode(settings.genesis())
    }
    fn context(&self, peer: Hash, direction: Direction) -> Hash {
        hash(
            b"native-pq-network-peer-context-v2",
            &[&self.id, &peer, &[direction as u8]],
        )
    }
    fn expectation<'a>(
        &self,
        peer: Hash,
        direction: Direction,
        sequence: u64,
        expiry: u64,
        now: u64,
        payload: &'a [u8],
    ) -> PqFrameExpectation<'a> {
        PqFrameExpectation {
            purpose: PEER_PURPOSE,
            network: self.network,
            owner_context: self.context(peer, direction),
            signer_key_id: match direction {
                Direction::Request => peer,
                Direction::Response => self.server_id,
            },
            owner_generation: self.record.generation,
            operation_sequence: sequence,
            expires_at: expiry,
            now,
            payload,
        }
    }
    pub(crate) fn verify_request(&self, wire: &[u8], now: u64) -> Result<VerifiedRequest> {
        self.verify_request_metered(wire, now, &mut || Ok(()))
    }
    fn verify_request_metered(
        &self,
        wire: &[u8],
        now: u64,
        before_verification: &mut impl FnMut() -> Result<()>,
    ) -> Result<VerifiedRequest> {
        let (frame, payload) = decode_wire(wire, REQUEST_MAGIC)?;
        let peer: Hash = frame[72..104].try_into().map_err(|_| "PQ_NETWORK_KEY")?;
        let verifier = self.peers.get(&peer).ok_or("PQ_NETWORK_UNKNOWN_PEER")?;
        let sequence = u64_field(frame, 112);
        let expiry = u64_field(frame, 120);
        ensure(
            (1..=i64::MAX as u64).contains(&sequence),
            "PQ_NETWORK_SEQUENCE",
        )?;
        let expected = self.expectation(peer, Direction::Request, sequence, expiry, now, payload);
        before_verification()?;
        let observed = verifier.verify(frame, &expected).map_err(crypto)?;
        let operation = hash(
            b"native-pq-network-operation-v2",
            &[observed.authenticated_statement()],
        );
        let request: Request = serde_json::from_slice(payload)?;
        ensure(
            serde_json::to_vec(&request)? == payload,
            "PQ_NETWORK_NONCANONICAL",
        )?;
        Ok(VerifiedRequest {
            policy: self.id,
            peer,
            sequence,
            expiry,
            operation,
            wire: wire.to_vec(),
            request,
        })
    }
    pub(crate) fn verify_retained_request(&self, wire: &[u8]) -> Result<VerifiedRequest> {
        // Historical validation checks a past signature at its own signed expiry.
        // It grants no live dispatch. Live ingress separately imposes current time.
        let (frame, _) = decode_wire(wire, REQUEST_MAGIC)?;
        self.verify_request(wire, u64_field(frame, 120))
    }
    pub(crate) fn verify_response(
        &self,
        wire: &[u8],
        request: &VerifiedRequest,
        now: u64,
    ) -> Result<PqResponse> {
        let (frame, payload) = decode_wire(wire, RESPONSE_MAGIC)?;
        self.server
            .verify(
                frame,
                &self.expectation(
                    request.peer,
                    Direction::Response,
                    request.sequence,
                    request.expiry,
                    now,
                    payload,
                ),
            )
            .map_err(crypto)?;
        let response: PqResponse = serde_json::from_slice(payload)?;
        ensure(
            serde_json::to_vec(&response)? == payload
                && response.schema == "native-pq-network-response-v2"
                && response.operation == hex::encode(request.operation),
            "PQ_NETWORK_RESPONSE_CONTEXT",
        )?;
        Ok(response)
    }
}

pub(crate) fn peer_ids_from_policy_record(bytes: &[u8]) -> Result<Vec<Hash>> {
    let record: PolicyRecord = serde_json::from_slice(bytes)?;
    ensure(
        serde_json::to_vec(&record)? == bytes && record.schema == PROFILE,
        "PQ_NETWORK_POLICY_RECORD",
    )?;
    record
        .peers
        .iter()
        .map(|s| {
            let raw = hex::decode(s).map_err(|_| "PQ_NETWORK_POLICY_RECORD")?;
            ml_dsa_65_key_id_from_spki(&raw).map_err(crypto)
        })
        .collect()
}

pub(crate) struct VerifiedRequest {
    pub(crate) policy: Hash,
    pub(crate) peer: Hash,
    pub(crate) sequence: u64,
    pub(crate) expiry: u64,
    pub(crate) operation: Hash,
    pub(crate) wire: Vec<u8>,
    pub(crate) request: Request,
}

fn u64_field(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(out)
}
fn statement(e: &PqFrameExpectation<'_>) -> Result<[u8; TPQ1_UNSIGNED_BYTES]> {
    let mut out = [0; TPQ1_UNSIGNED_BYTES];
    out[..8].copy_from_slice(&[b'T', b'P', b'Q', b'1', 1, 0x65, e.purpose, 0]);
    out[8..40].copy_from_slice(&e.network);
    out[40..72].copy_from_slice(&e.owner_context);
    out[72..104].copy_from_slice(&e.signer_key_id);
    out[104..112].copy_from_slice(&e.owner_generation.to_be_bytes());
    out[112..120].copy_from_slice(&e.operation_sequence.to_be_bytes());
    out[120..128].copy_from_slice(&e.expires_at.to_be_bytes());
    out[128..].copy_from_slice(&payload_commitment(e.payload).map_err(crypto)?);
    Ok(out)
}
fn encode_wire(magic: &[u8; 4], frame: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ensure(
        frame.len() == TPQ1_SIGNED_BYTES && payload.len() <= MAX_WIRE - 8 - TPQ1_SIGNED_BYTES,
        "PQ_NETWORK_WIRE_LIMIT",
    )?;
    let mut out = Vec::with_capacity(8 + frame.len() + payload.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    out.extend_from_slice(payload);
    Ok(out)
}
fn decode_wire<'a>(wire: &'a [u8], magic: &[u8; 4]) -> Result<(&'a [u8], &'a [u8])> {
    ensure(
        (8 + TPQ1_SIGNED_BYTES..=MAX_WIRE).contains(&wire.len()),
        "PQ_NETWORK_WIRE_LIMIT",
    )?;
    ensure(&wire[..4] == magic, "PQ_NETWORK_WIRE_VERSION")?;
    let length =
        u32::from_be_bytes(wire[4..8].try_into().map_err(|_| "PQ_NETWORK_WIRE_LIMIT")?) as usize;
    ensure(
        length == wire.len() - 8 - TPQ1_SIGNED_BYTES,
        "PQ_NETWORK_WIRE_LIMIT",
    )?;
    Ok((
        &wire[8..8 + TPQ1_SIGNED_BYTES],
        &wire[8 + TPQ1_SIGNED_BYTES..],
    ))
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PqResponse {
    pub schema: String,
    pub operation: String,
    pub ok: bool,
    pub value: Value,
}

pub struct PreparedPqRequest {
    verified: VerifiedRequest,
}
impl PreparedPqRequest {
    pub fn wire(&self) -> &[u8] {
        &self.verified.wire
    }
    pub fn operation_id(&self) -> Hash {
        self.verified.operation
    }
}

pub struct PqClient {
    policy: Arc<PqNetworkPolicy>,
    signer: PqNativeSigningKey,
}
impl PqClient {
    pub fn new(policy: Arc<PqNetworkPolicy>, signer: PqNativeSigningKey) -> Result<Self> {
        ensure(
            policy.peers.contains_key(&signer.public_key_id()),
            "PQ_NETWORK_UNKNOWN_PEER",
        )?;
        Ok(Self { policy, signer })
    }
    pub fn prepare(
        &self,
        sequence: u64,
        expires_at: u64,
        request: Request,
    ) -> Result<PreparedPqRequest> {
        let now = super::now()?;
        ensure(
            expires_at >= now && expires_at - now <= MAX_LIFETIME_SECONDS,
            "PQ_NETWORK_LIFETIME",
        )?;
        let payload = serde_json::to_vec(&request)?;
        let expected = self.policy.expectation(
            self.signer.public_key_id(),
            Direction::Request,
            sequence,
            expires_at,
            now,
            &payload,
        );
        let frame = self
            .signer
            .sign_statement(&statement(&expected)?, &expected)
            .map_err(crypto)?;
        let wire = encode_wire(REQUEST_MAGIC, &frame, &payload)?;
        Ok(PreparedPqRequest {
            verified: self.policy.verify_request(&wire, now)?,
        })
    }
    pub fn send(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<PqResponse> {
        ensure(
            prepared.verified.policy == self.policy.id
                && prepared.verified.peer == self.signer.public_key_id(),
            "PQ_NETWORK_CLIENT_CONTEXT",
        )?;
        ensure(
            !budget.is_zero() && budget <= Duration::from_secs(10),
            "PQ_NETWORK_CLIENT_BUDGET",
        )?;
        let end = Instant::now() + budget;
        let mut stream = TcpStream::connect_timeout(&address, budget)?;
        super::write_frame_deadline(&mut stream, prepared.wire(), end)?;
        let response = super::read_frame_deadline(&mut stream, end)?;
        self.policy
            .verify_response(&response, &prepared.verified, super::now()?)
    }
}

pub struct PqServer {
    policy: Arc<PqNetworkPolicy>,
    signer: PqNativeSigningKey,
}
impl PqServer {
    pub fn new(policy: Arc<PqNetworkPolicy>, signer: PqNativeSigningKey) -> Result<Self> {
        ensure(
            signer.public_key_id() == policy.server_id
                && hex::encode(signer.public_spki()) == policy.record.server_spki,
            "PQ_NETWORK_SERVER_KEY",
        )?;
        Ok(Self { policy, signer })
    }
    fn response(&self, request: &VerifiedRequest, result: Result<Value>) -> Result<Vec<u8>> {
        let (ok, value) = match result {
            Ok(value) => (true, value),
            Err(error) => (false, json!({"error":error.to_string()})),
        };
        let (ok, value) = if super::now()? > request.expiry {
            (false, json!({"error":"PQ_NETWORK_EXPIRED_UNCONFIRMED"}))
        } else {
            (ok, value)
        };
        let response = PqResponse {
            schema: "native-pq-network-response-v2".into(),
            operation: hex::encode(request.operation),
            ok,
            value,
        };
        let payload = serde_json::to_vec(&response)?;
        let expected = self.policy.expectation(
            request.peer,
            Direction::Response,
            request.sequence,
            request.expiry,
            request.expiry,
            &payload,
        );
        // Persist completion under the original signed expiry. A live client
        // independently rejects this receipt after expiry; no lease is renewed.
        let frame = self
            .signer
            .sign_statement(&statement(&expected)?, &expected)
            .map_err(crypto)?;
        encode_wire(RESPONSE_MAGIC, &frame, &payload)
    }
    fn read_request(
        &self,
        node: &Mutex<Node>,
        stream: &mut TcpStream,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        // Charge the original durable owner before reading or allocating a body.
        node.lock()
            .map_err(|_| "PQ_NETWORK_OWNER")?
            .charge_pq_ingress(&self.policy, true, 0, false)?;
        let mut prefix = [0; 4];
        super::read_exact_deadline(stream, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        ensure((1..=MAX_WIRE).contains(&length), "PQ_NETWORK_WIRE_LIMIT")?;
        node.lock()
            .map_err(|_| "PQ_NETWORK_OWNER")?
            .charge_pq_ingress(&self.policy, false, length as u64, false)?;
        let mut wire = vec![0; length];
        super::read_exact_deadline(stream, &mut wire, deadline)?;
        Ok(wire)
    }
    fn handle(&self, node: &Mutex<Node>, wire: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        let now = super::now()?;
        let verified = self.policy.verify_request_metered(wire, now, &mut || {
            node.lock()
                .map_err(|_| "PQ_NETWORK_OWNER")?
                .charge_pq_ingress(&self.policy, false, 0, true)
        })?;
        ensure(
            verified.expiry - now <= MAX_LIFETIME_SECONDS,
            "PQ_NETWORK_LIFETIME",
        )?;
        let (begin, settings) = {
            let mut owner = node.lock().map_err(|_| "PQ_NETWORK_OWNER")?;
            let begin = owner.begin_pq_network_request(&self.policy, &verified)?;
            (begin, owner.settings().clone())
        };
        let (epoch, expected_epoch) = match begin {
            crate::store::pq_network::PqReplay::Cached(response) => return Ok(response),
            crate::store::pq_network::PqReplay::Execute(epoch, expected) => (epoch, expected),
        };
        let check = || {
            if Instant::now() >= deadline {
                return Err(Error::new(ErrorCode::PqNetworkDeadline));
            }
            if super::now()? > verified.expiry {
                return Err(Error::new(ErrorCode::PqNetworkExpired));
            }
            if epoch.load(Ordering::Acquire) != expected_epoch {
                return Err(Error::new(ErrorCode::PqNetworkRevoked));
            }
            Ok(())
        };
        let result = super::dispatch_shared_with_execution_observation(
            node,
            verified.request.clone(),
            &mut |_| check(),
            |packet| WorkCheckedPacket::verify_with_progress(packet, &mut |_| check()),
            &trnm_mvcc_fee::pon_executor::ExecutionControl::new(&|_| check(), &()),
            super::SubmitDispatchContext {
                packet_settings: Some(&settings),
                ..super::SubmitDispatchContext::default()
            },
        );
        // Complete outcomes, including errors, consume this operation sequence.
        // A caller can issue a new sequence, but cannot change this retained result.
        let response = self.response(&verified, result)?;
        node.lock()
            .map_err(|_| "PQ_NETWORK_OWNER")?
            .finish_pq_network_request(&self.policy, &verified, &response, expected_epoch)?;
        Ok(response)
    }
}

#[derive(Default, Debug, Serialize)]
pub struct PqNetworkMetrics {
    pub accepted: u64,
    pub refused: u64,
}

/// Actual native TCP service, deliberately loopback-only until public resource
/// qualification. Every accepted frame takes the real ML-DSA verifier and the
/// same Node admission/execution path; no transport signature adds chainwork.
pub fn serve_pq_authenticated(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PqServer,
) -> Result<PqNetworkMetrics> {
    ensure(
        listener.local_addr()?.ip().is_loopback(),
        "PQ_NETWORK_LOOPBACK_ONLY",
    )?;
    ensure(
        !lifetime.is_zero() && lifetime <= Duration::from_secs(3600),
        "PQ_NETWORK_SERVER_BUDGET",
    )?;
    node.check_pq_network_policy(&server.policy)?;
    listener.set_nonblocking(true)?;
    let owner = Mutex::new(node);
    let end = Instant::now() + lifetime;
    let mut metrics = PqNetworkMetrics::default();
    while !stop.load(Ordering::Acquire) && Instant::now() < end {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let deadline = end.min(Instant::now() + Duration::from_secs(10));
                let result = server
                    .read_request(&owner, &mut stream, deadline)
                    .and_then(|wire| server.handle(&owner, &wire, deadline))
                    .and_then(|response| {
                        super::write_frame_deadline(&mut stream, &response, deadline)
                    });
                if result.is_ok() {
                    metrics.accepted += 1;
                } else {
                    metrics.refused += 1;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(metrics)
}

#[cfg(all(test, feature = "pq-native-openssl"))]
mod tests;

#[cfg(test)]
mod canonical_tests;
