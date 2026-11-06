//! Explicit fresh PQ-only native network owner. This authenticates transport,
//! never account spending, task signatures, PoN work or model-install authority.
//! Both explicitly selected loopback profiles retain bounded durable replay
//! ownership. Original PNQ2 is signed plaintext. The distinct TLS-required owner
//! uses a hybrid encrypted channel; neither profile qualifies public service,
//! account migration, private tasks or WAN deployment.
use super::{Request, WorkCheckedPacket};
use crate::pq_rollback_witness::{observe_operation, observe_phase};
use crate::{ensure, Error, ErrorCode, Node, Result, Settings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, TryLockError,
    },
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::{
    crypto_profile::{
        BoundCryptoProfile, CryptoProfile, CryptoProfileId, ProfileBinding, ProfileScope,
    },
    pon_wire::{hash, Hash},
    pq_frame::{
        ml_dsa_65_key_id_from_spki, payload_commitment, PqFrameExpectation, TPQ1_SIGNED_BYTES,
        TPQ1_UNSIGNED_BYTES,
    },
    pq_legacy_profile::{
        MAX_LIFETIME_SECONDS, MAX_PEERS, MAX_SIGNED_PAYLOAD_BYTES, OPERATION_DOMAIN,
        PEER_CONTEXT_DOMAIN, PEER_PURPOSE, POLICY_DOMAIN, REQUEST_DIRECTION, REQUEST_MAGIC,
        RESPONSE_DIRECTION, RESPONSE_MAGIC, RESPONSE_SCHEMA, TRANSPORT_MODE,
    },
};

pub use trnm_protocol::pq_legacy_profile::PROFILE;
pub(crate) use trnm_protocol::pq_legacy_profile::{
    MAX_INBOUND_VERIFICATIONS, MAX_INGRESS_BYTES, MAX_INGRESS_CONNECTIONS, MAX_LEDGER_BYTES,
    MAX_RECORDS, MAX_WIRE,
};

mod tls_profile;
pub use tls_profile::{PqTlsPins, TLS_HANDSHAKE_LIMIT, TLS_PROFILE, TLS_TRANSPORT_MODE};

#[derive(Clone, Copy)]
#[repr(u8)]
enum Direction {
    Request = REQUEST_DIRECTION,
    Response = RESPONSE_DIRECTION,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<PqTlsPins>,
}

/// Operator-supplied pins. No key from an incoming frame can enter this roster.
pub struct PqNetworkPolicy {
    record: PolicyRecord,
    bytes: Vec<u8>,
    id: Hash,
    // A fixed owner selection, never deserialized or selected by a TPQ1 frame.
    // The existing policy record and signed owner context stay byte-identical.
    crypto_profile: BoundCryptoProfile,
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
        let crypto_profile = CryptoProfile::LegacyMlDsa65V1
            .bind(ProfileBinding {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
                protocol_version: 2,
                scope: ProfileScope::NativePeer,
                activation_height: 0,
                retirement_height: None,
            })
            .map_err(crypto)?;
        let server_id = ml_dsa_65_key_id_from_spki(server_spki).map_err(crypto)?;
        let server = PqNativeVerifier::from_pinned_spki(server_spki, server_id).map_err(crypto)?;
        let mut peers = BTreeMap::new();
        let mut public = BTreeMap::new();
        for spki in peer_spkis {
            ensure(peers.len() < MAX_PEERS, "PQ_NETWORK_PEER_LIMIT")?;
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
            transport_confidentiality: TRANSPORT_MODE.into(),
            tls: None,
        };
        let bytes = serde_json::to_vec(&record)?;
        let id = hash(POLICY_DOMAIN, &[&bytes]);
        Ok(Self {
            record,
            bytes,
            id,
            crypto_profile,
            network: settings.network(),
            server_id,
            server,
            peers,
        })
    }

    pub fn id(&self) -> Hash {
        self.id
    }
    /// Identifies the existing fixed TPQ1 algorithm/encoding/hash contract.
    /// This descriptor does not activate another wire or authorize an effect.
    pub fn crypto_profile_id(&self) -> CryptoProfileId {
        self.crypto_profile.id()
    }
    /// Compare a caller's declaration to the independently selected owner.
    /// A declaration can never select a weaker or experimental configuration.
    /// PNQ2 itself has no new profile field; its original signed bytes remain.
    pub fn require_profile_claim(&self, claimed: CryptoProfileId) -> Result<()> {
        ensure(
            claimed == self.crypto_profile_id(),
            "PQ_NETWORK_CRYPTO_PROFILE",
        )
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
            self.context_domain(),
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
        let authenticated = self.authenticate_request(wire, now, before_verification)?;
        Ok(VerifiedRequest {
            policy: self.id,
            peer: authenticated.peer,
            sequence: authenticated.sequence,
            expiry: authenticated.expiry,
            operation: authenticated.operation,
            wire: wire.to_vec(),
            request: authenticated.request,
        })
    }
    // Shared signature/encoding verification returns only private observations.
    // The caller separately selects live verification or retained-record audit;
    // historical verification never constructs a live VerifiedRequest.
    fn authenticate_request(
        &self,
        wire: &[u8],
        now: u64,
        before_verification: &mut impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedRequest> {
        let (frame, payload) = decode_wire(wire, self.request_magic())?;
        let peer: Hash = frame[72..104].try_into().map_err(|_| "PQ_NETWORK_KEY")?;
        let verifier = self.peers.get(&peer).ok_or("PQ_NETWORK_UNKNOWN_PEER")?;
        let sequence = u64_field(frame, 112);
        let expiry = u64_field(frame, 120);
        ensure(
            (1..=i64::MAX as u64).contains(&sequence),
            "PQ_NETWORK_SEQUENCE",
        )?;
        // Reserve the original durable attempt before deriving the payload-
        // bound cryptographic expectation. Even a bounded invalid payload can
        // otherwise consume hashing and allocation before the owner is charged.
        // Preserve peer/sequence checks and all original verification limits.
        before_verification()?;
        let expected = self.expectation(peer, Direction::Request, sequence, expiry, now, payload);
        // The live server already rejects signed expiries beyond 60 seconds,
        // but previously did so only AFTER ML-DSA and payload parsing. Refuse
        // the same impossible future interval before spending verifier CPU.
        // Expired packets retain the verifier's existing refusal semantics;
        // retained historical validation uses its signed expiry as "now".
        ensure(
            expiry <= now || expiry - now <= MAX_LIFETIME_SECONDS,
            "PQ_NETWORK_LIFETIME",
        )?;
        let observed = verifier.verify(frame, &expected).map_err(crypto)?;
        let operation = hash(
            self.operation_domain(),
            &[observed.authenticated_statement()],
        );
        let request: Request = serde_json::from_slice(payload)?;
        ensure(
            serde_json::to_vec(&request)? == payload,
            "PQ_NETWORK_NONCANONICAL",
        )?;
        Ok(AuthenticatedRequest {
            peer,
            sequence,
            expiry,
            operation,
            request,
        })
    }
    pub(crate) fn verify_retained_request(&self, wire: &[u8]) -> Result<RetainedRequest> {
        // Historical validation checks a past signature at its own signed expiry.
        // It grants no live dispatch. Live ingress separately imposes current time.
        let (frame, _) = decode_wire(wire, self.request_magic())?;
        let authenticated =
            self.authenticate_request(wire, u64_field(frame, 120), &mut || Ok(()))?;
        Ok(RetainedRequest {
            policy: self.id,
            peer: authenticated.peer,
            sequence: authenticated.sequence,
            expiry: authenticated.expiry,
            operation: authenticated.operation,
        })
    }
    pub(crate) fn verify_response(
        &self,
        wire: &[u8],
        request: &VerifiedRequest,
        now: u64,
    ) -> Result<PqResponse> {
        self.verify_response_fields(
            wire,
            request.peer,
            request.sequence,
            request.expiry,
            request.operation,
            now,
        )
    }
    /// Recheck retained response evidence without returning a live response.
    pub(crate) fn verify_retained_response(
        &self,
        wire: &[u8],
        request: &RetainedRequest,
    ) -> Result<()> {
        ensure(request.policy == self.id, "PQ_NETWORK_CONTEXT")?;
        self.verify_response_fields(
            wire,
            request.peer,
            request.sequence,
            request.expiry,
            request.operation,
            request.expiry,
        )
        .map(|_| ())
    }
    fn verify_response_fields(
        &self,
        wire: &[u8],
        peer: Hash,
        sequence: u64,
        expiry: u64,
        operation: Hash,
        now: u64,
    ) -> Result<PqResponse> {
        let (frame, payload) = decode_wire(wire, self.response_magic())?;
        self.server
            .verify(
                frame,
                &self.expectation(peer, Direction::Response, sequence, expiry, now, payload),
            )
            .map_err(crypto)?;
        let response: PqResponse = serde_json::from_slice(payload)?;
        ensure(
            serde_json::to_vec(&response)? == payload
                && response.schema == self.response_schema()
                && response.operation == hex::encode(operation),
            "PQ_NETWORK_RESPONSE_CONTEXT",
        )?;
        Ok(response)
    }
}

pub(crate) fn peer_ids_from_policy_record(bytes: &[u8]) -> Result<Vec<Hash>> {
    let record: PolicyRecord = serde_json::from_slice(bytes)?;
    ensure(
        serde_json::to_vec(&record)? == bytes,
        "PQ_NETWORK_POLICY_RECORD",
    )?;
    record.validate_transport()?;
    record
        .peers
        .iter()
        .map(|s| {
            let raw = hex::decode(s).map_err(|_| "PQ_NETWORK_POLICY_RECORD")?;
            ml_dsa_65_key_id_from_spki(&raw).map_err(crypto)
        })
        .collect()
}

// This observation is private to the verification owner. It is not a live
// request and cannot reach Node admission without the live verifier's wrapper.
struct AuthenticatedRequest {
    peer: Hash,
    sequence: u64,
    expiry: u64,
    operation: Hash,
    request: Request,
}

/// Historical signature facts only. Deliberately carries no request body or
/// wire, and has no conversion/Deref to the live request accepted by admission.
pub(crate) struct RetainedRequest {
    policy: Hash,
    peer: Hash,
    sequence: u64,
    expiry: u64,
    operation: Hash,
}
impl RetainedRequest {
    pub(crate) fn peer(&self) -> Hash {
        self.peer
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn expiry(&self) -> u64 {
        self.expiry
    }
    pub(crate) fn operation(&self) -> Hash {
        self.operation
    }
}

/// Constructed only by the live request verifier. Private fields prevent other
/// crate modules from promoting historical observations into current requests.
/// The original current-time, replay, revocation and owner checks remain needed.
pub(crate) struct VerifiedRequest {
    policy: Hash,
    peer: Hash,
    sequence: u64,
    expiry: u64,
    operation: Hash,
    wire: Vec<u8>,
    request: Request,
}
impl VerifiedRequest {
    pub(crate) fn policy(&self) -> Hash {
        self.policy
    }
    pub(crate) fn peer(&self) -> Hash {
        self.peer
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn expiry(&self) -> u64 {
        self.expiry
    }
    pub(crate) fn operation(&self) -> Hash {
        self.operation
    }
    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }
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
fn require_signed_payload_bound(length: usize) -> Result<()> {
    ensure(length <= MAX_SIGNED_PAYLOAD_BYTES, "PQ_NETWORK_WIRE_LIMIT")
}
fn encode_wire(magic: &[u8; 4], frame: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ensure(frame.len() == TPQ1_SIGNED_BYTES, "PQ_NETWORK_WIRE_LIMIT")?;
    require_signed_payload_bound(payload.len())?;
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
    #[cfg(test)]
    before_response_completion: Option<Box<dyn Fn(Instant) + Send + Sync>>,
}
impl PqClient {
    pub fn new(policy: Arc<PqNetworkPolicy>, signer: PqNativeSigningKey) -> Result<Self> {
        ensure(
            policy.peers.contains_key(&signer.public_key_id()),
            "PQ_NETWORK_UNKNOWN_PEER",
        )?;
        Ok(Self {
            policy,
            signer,
            #[cfg(test)]
            before_response_completion: None,
        })
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
        // A locally supplied sequence outside the native signed-wire domain
        // cannot pass the receiver's existing check. Reject it before JSON
        // serialization and costly ML-DSA signing, not after creating a frame.
        ensure(
            (1..=i64::MAX as u64).contains(&sequence),
            "PQ_NETWORK_SEQUENCE",
        )?;
        let payload = serde_json::to_vec(&request)?;
        // This client must not hash/sign a body the original PNQ2 wire bound
        // would reject after ML-DSA has already done expensive work.
        require_signed_payload_bound(payload.len())?;
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
        let wire = encode_wire(self.policy.request_magic(), &frame, &payload)?;
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
        // A TLS-required policy cannot reach the original plaintext socket,
        // even if the caller supplies an otherwise valid prepared request.
        self.policy.require_plaintext()?;
        self.check_send(address, prepared, budget)?;
        let end = Instant::now() + budget;
        let mut stream = TcpStream::connect_timeout(&address, budget)?;
        super::write_frame_deadline(&mut stream, prepared.wire(), end)?;
        let response = super::read_frame_deadline(&mut stream, end)?;
        self.finish_response(&response, prepared, end)
    }
    fn check_send(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<()> {
        ensure(
            prepared.verified.policy == self.policy.id
                && prepared.verified.peer == self.signer.public_key_id(),
            "PQ_NETWORK_CLIENT_CONTEXT",
        )?;
        ensure(
            !budget.is_zero() && budget <= Duration::from_secs(10),
            "PQ_NETWORK_CLIENT_BUDGET",
        )?;
        // PNQ2 is authenticated plaintext for explicitly local development.
        // The server already refuses non-loopback listeners; the public client
        // must enforce the same boundary before a signed payload reaches a
        // caller-selected remote TCP endpoint (or leaks across a public route).
        ensure(address.ip().is_loopback(), "PQ_NETWORK_LOOPBACK_ONLY")?;
        // Preparation checked its original expiry, but caller queueing may
        // outlive the signed lease. Refuse a stale packet before TCP; the
        // receiving node independently checks expiry at the live boundary.
        ensure(
            super::now()? <= prepared.verified.expiry,
            "PQ_NETWORK_EXPIRED_UNCONFIRMED",
        )?;
        Ok(())
    }
    fn finish_response(
        &self,
        response: &[u8],
        prepared: &PreparedPqRequest,
        end: Instant,
    ) -> Result<PqResponse> {
        let verified = self
            .policy
            .verify_response(response, &prepared.verified, super::now()?)?;
        #[cfg(test)]
        if let Some(before_completion) = self.before_response_completion.as_ref() {
            before_completion(end);
        }
        // Receiving the complete frame is not completion: canonical decoding,
        // payload hashing and ML-DSA verification still spend the original
        // interval. A late authenticated receipt cannot become a timely ACK.
        // Refusal neither refunds the server's spent sequence nor retries it.
        check_live_request(end, None)?;
        ensure(
            super::now()? <= prepared.verified.expiry,
            "PQ_NETWORK_EXPIRED_UNCONFIRMED",
        )?;
        Ok(verified)
    }
}

pub struct PqServer {
    policy: Arc<PqNetworkPolicy>,
    signer: PqNativeSigningKey,
}

// Private transport evidence. A public caller cannot label a byte slice TLS.
enum TransportAdmission {
    Plaintext,
    #[cfg(feature = "pq-native-openssl")]
    Tls {
        policy: Hash,
        peer: Hash,
    },
}
impl TransportAdmission {
    fn require(&self, policy: &PqNetworkPolicy, _peer: Option<Hash>) -> Result<()> {
        match self {
            Self::Plaintext => policy.require_plaintext(),
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls {
                policy: admitted,
                peer: tls_peer,
            } => {
                policy.tls_pins()?;
                ensure(
                    *admitted == policy.id && _peer.is_none_or(|id| id == *tls_peer),
                    "PQ_TLS_SIGNER_CHANNEL_BINDING",
                )
            }
        }
    }
}

// Queueing for the native owner is part of the caller's original interval.
// This guard does not renew the wire lease, refund an attempted signature or
// replace the execution owner's cancellation checks.
fn check_live_request(deadline: Instant, expiry: Option<u64>) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::new(ErrorCode::PqNetworkDeadline));
    }
    if let Some(expiry) = expiry {
        if super::now()? > expiry {
            return Err(Error::new(ErrorCode::PqNetworkExpired));
        }
    }
    Ok(())
}

fn lock_live_owner(
    node: &Mutex<Node>,
    deadline: Instant,
    expiry: Option<u64>,
) -> Result<MutexGuard<'_, Node>> {
    loop {
        check_live_request(deadline, expiry)?;
        match node.try_lock() {
            Ok(owner) => {
                check_live_request(deadline, expiry)?;
                return Ok(owner);
            }
            Err(TryLockError::Poisoned(_)) => return Err("PQ_NETWORK_OWNER".into()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(2)),
        }
    }
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
            schema: self.policy.response_schema().into(),
            operation: hex::encode(request.operation),
            ok,
            value,
        };
        let payload = serde_json::to_vec(&response)?;
        // Never sign an oversized terminal response that cannot be persisted
        // or relayed under the same fixed native network wire limit.
        require_signed_payload_bound(payload.len())?;
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
        encode_wire(self.policy.response_magic(), &frame, &payload)
    }
    fn read_request(
        &self,
        node: &Mutex<Node>,
        stream: &mut TcpStream,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        self.charge_connection(node, deadline)?;
        self.read_request_body(node, deadline, &mut |bytes| {
            super::read_exact_deadline(stream, bytes, deadline)
        })
    }
    fn charge_connection(&self, node: &Mutex<Node>, deadline: Instant) -> Result<()> {
        // Charge the original durable owner before reading or allocating a body.
        lock_live_owner(node, deadline, None)?.charge_pq_ingress_with_check(
            &self.policy,
            true,
            0,
            false,
            deadline,
            &mut || check_live_request(deadline, None),
        )
    }
    fn read_request_body(
        &self,
        node: &Mutex<Node>,
        deadline: Instant,
        read_exact: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut prefix = [0; 4];
        read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        ensure((1..=MAX_WIRE).contains(&length), "PQ_NETWORK_WIRE_LIMIT")?;
        lock_live_owner(node, deadline, None)?.charge_pq_ingress_with_check(
            &self.policy,
            false,
            length as u64,
            false,
            deadline,
            &mut || check_live_request(deadline, None),
        )?;
        check_live_request(deadline, None)?;
        let mut wire = vec![0; length];
        read_exact(&mut wire)?;
        Ok(wire)
    }
    fn handle(&self, node: &Mutex<Node>, wire: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        self.handle_admitted(node, wire, deadline, &TransportAdmission::Plaintext)
    }
    fn handle_admitted(
        &self,
        node: &Mutex<Node>,
        wire: &[u8],
        deadline: Instant,
        transport: &TransportAdmission,
    ) -> Result<Vec<u8>> {
        transport.require(&self.policy, None)?;
        check_live_request(deadline, None)?;
        // Decode only the already-bounded frame here. This untrusted expiry
        // can cause refusal only; the canonical verifier still authenticates
        // it before begin, cached replay, execution or response production.
        let (frame, _) = decode_wire(wire, self.policy.request_magic())?;
        let expiry = u64_field(frame, 120);
        let now = super::now()?;
        let verified = self.policy.verify_request_metered(wire, now, &mut || {
            lock_live_owner(node, deadline, Some(expiry))?.charge_pq_ingress_with_check(
                &self.policy,
                false,
                0,
                true,
                deadline,
                &mut || check_live_request(deadline, Some(expiry)),
            )?;
            // A synchronous durable charge cannot be preempted. If it
            // overruns, retain the spent attempt and skip signature CPU.
            check_live_request(deadline, Some(expiry))
        })?;
        // The non-interruptible signature work and its preceding durable
        // charge may have crossed the original interval. Keep the charge;
        // refuse a new operation or a cached response under stale authority.
        check_live_request(deadline, Some(verified.expiry))?;
        transport.require(&self.policy, Some(verified.peer))?;
        ensure(
            verified.expiry - now <= MAX_LIFETIME_SECONDS,
            "PQ_NETWORK_LIFETIME",
        )?;
        let (begin, settings) = {
            let mut owner = lock_live_owner(node, deadline, Some(verified.expiry))?;
            let begin = owner.begin_pq_network_request_with_check(
                &self.policy,
                &verified,
                deadline,
                &mut || check_live_request(deadline, Some(verified.expiry)),
            )?;
            (begin, owner.settings().clone())
        };
        let (epoch, expected_epoch) = match begin {
            crate::store::pq_network::PqReplay::Cached(response) => {
                check_live_request(deadline, Some(verified.expiry))?;
                return Ok(response);
            }
            crate::store::pq_network::PqReplay::Execute(epoch, expected) => (epoch, expected),
        };
        let check = || {
            check_live_request(deadline, Some(verified.expiry))?;
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
        let completed_successfully = result.is_ok();
        let response = self.response(&verified, result)?;
        node.lock()
            .map_err(|_| "PQ_NETWORK_OWNER")?
            .finish_pq_network_request(&self.policy, &verified, &response, expected_epoch)?;
        // Finish records the actual outcome even after cancellation; skipping
        // it would lose the completed operation and strand the next sequence.
        // Its completion is not permission to return a late successful ACK.
        check_live_request(deadline, completed_successfully.then_some(verified.expiry))?;
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
    server.policy.require_plaintext()?;
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
                let result = observe_operation!(
                    observation,
                    crate::pq_rollback_witness::test_observation::Kind::TcpRequest,
                    {
                        #[cfg(test)]
                        if let Some(observation) = observation.as_ref() {
                            observation.deadlines(Some(deadline), deadline);
                        }
                        observe_phase!(
                            observation,
                            TcpReadRequest,
                            server.read_request(&owner, &mut stream, deadline)
                        )
                        .and_then(|wire| {
                            observe_phase!(
                                observation,
                                TcpHandle,
                                server.handle(&owner, &wire, deadline)
                            )
                        })
                        .and_then(|response| {
                            observe_phase!(
                                observation,
                                TcpWriteFrame,
                                super::write_frame_deadline(&mut stream, &response, deadline)
                            )
                        })
                    }
                );
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
pub(crate) mod canonical_tests;

#[cfg(test)]
mod live_admission_tests;
