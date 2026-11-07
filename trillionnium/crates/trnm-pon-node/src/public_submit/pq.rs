//! Explicit native-PQ mutations and PQHistoryV4 reads share pinned context.
//! This selection owns no sequence, retry, membership or authorization cache.
//! The recovery journal and bounded orchestrator must account for each call.
//! HistoryV4 remains signed plaintext on loopback even when the separate
//! native mutation connection selects hybrid TLS. This is not a private-task
//! or public/WAN service confidentiality qualification.
use crate::ingress::pq_network::{
    tls::PqTlsClient, PqClient, PqNetworkPolicy, PqResponseEvidence, PreparedPqRequest,
};
use crate::ingress::public_v3::{
    call_public_history_pq_v4, PqPublicIdentity, PublicClientMetrics, PublicPolicy, PublicReply,
    Request as HistoryRequest,
};
use crate::ingress::Request;
use crate::{ensure, Node, Result, Settings};
use serde::Serialize;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use trnm_protocol::pon_wire::{hash, Hash};

pub const PQ_RECOVERY_HISTORY_TRANSPORT: &str = "pq-signed-plaintext-loopback";

/// Closed transport selection. TLS can only call the actual TLS exchange;
/// plaintext retains its explicit authenticated-loopback development boundary.
#[derive(Clone, Copy)]
pub enum PqRecoveryTransport<'a> {
    AuthenticatedLoopback(&'a PqClient),
    HybridTlsLoopback(&'a PqTlsClient),
}
impl PqRecoveryTransport<'_> {
    fn client(&self) -> &PqClient {
        match self {
            Self::AuthenticatedLoopback(client) => client,
            Self::HybridTlsLoopback(client) => client.selected_client(),
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::AuthenticatedLoopback(client) => client.require_plaintext_selection(),
            // This type is constructed only by the existing validated TLS
            // context constructor and retains an immutable selected policy.
            Self::HybridTlsLoopback(_) => Ok(()),
        }
    }
    fn mode(&self) -> &'static str {
        match self {
            Self::AuthenticatedLoopback(_) => "authenticated-plaintext-loopback",
            Self::HybridTlsLoopback(_) => "hybrid-tls13-loopback",
        }
    }
    fn send_until(
        &self,
        address: SocketAddr,
        request: &PreparedPqRequest,
        deadline: Instant,
    ) -> Result<PqResponseEvidence> {
        match self {
            Self::AuthenticatedLoopback(client) => {
                client.send_with_evidence_until(address, request, deadline)
            }
            Self::HybridTlsLoopback(client) => {
                client.send_with_evidence_until(address, request, deadline)
            }
        }
    }
    fn send(
        &self,
        address: SocketAddr,
        request: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<PqResponseEvidence> {
        match self {
            Self::AuthenticatedLoopback(client) => {
                client.send_with_evidence(address, request, budget)
            }
            Self::HybridTlsLoopback(client) => client.send_with_evidence(address, request, budget),
        }
    }
}

#[derive(Serialize)]
struct Context {
    namespace: &'static str,
    network: String,
    parameters: String,
    genesis: String,
    native_policy: String,
    native_generation: u64,
    native_transport: &'static str,
    server_key: String,
    server_spki: String,
    peer_key: String,
    history_policy: String,
    history_transport: &'static str,
    native_address: String,
    history_address: String,
}

pub struct PinnedPqRecoveryClient<'a> {
    transport: PqRecoveryTransport<'a>,
    native_address: SocketAddr,
    history_address: SocketAddr,
    history_identity: &'a PqPublicIdentity,
    history_policy: PublicPolicy,
    server_spki: Vec<u8>,
    packet_settings: Settings,
    context: Hash,
}
impl<'a> PinnedPqRecoveryClient<'a> {
    pub fn new(
        node: &Node,
        transport: PqRecoveryTransport<'a>,
        native_address: SocketAddr,
        history_address: SocketAddr,
        history_identity: &'a PqPublicIdentity,
        history_policy: PublicPolicy,
    ) -> Result<Self> {
        transport.validate()?;
        ensure(
            native_address.ip().is_loopback() && history_address.ip().is_loopback(),
            "PQ_PARENT_RECOVERY_LOOPBACK_ONLY",
        )?;
        PublicPolicy::new(
            history_policy.bits,
            Duration::from_millis(history_policy.lifetime_ms),
        )?;
        let policy = transport.client().policy();
        // Inspect the actual selected Node owner, including when account
        // Settings still happen to use the classical development profile.
        node.check_pq_network_policy(policy)?;
        ensure(
            history_identity.public_key() == hex::encode(transport.client().peer_key_id()),
            "PQ_PARENT_RECOVERY_CALLER_PIN",
        )?;
        let server_spki = policy.pinned_server_spki()?;
        let mut selected = Self {
            transport,
            native_address,
            history_address,
            history_identity,
            history_policy,
            server_spki,
            packet_settings: node.settings().clone(),
            context: [0; 32],
        };
        selected.context = selected.compute_context(node)?;
        Ok(selected)
    }
    fn compute_context(&self, node: &Node) -> Result<Hash> {
        node.check_pq_network_policy(self.policy())?;
        let settings = node.settings();
        let record = Context {
            namespace: "trnm-pq-parent-recovery-client-v1",
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            native_policy: hex::encode(self.policy().id()),
            native_generation: self.policy().generation(),
            native_transport: self.transport.mode(),
            server_key: hex::encode(self.policy().server_key_id()),
            server_spki: hex::encode(&self.server_spki),
            peer_key: hex::encode(self.peer_key_id()),
            history_policy: hex::encode(self.history_policy.pq_history_id()),
            history_transport: PQ_RECOVERY_HISTORY_TRANSPORT,
            native_address: self.native_address.to_string(),
            history_address: self.history_address.to_string(),
        };
        Ok(hash(
            b"TRNM/PoN/PqParentRecovery/ClientContext/v1\0",
            &[&serde_json::to_vec(&record)?],
        ))
    }
    pub fn validate_for_node(&self, node: &Node) -> Result<()> {
        self.transport.validate()?;
        ensure(
            self.compute_context(node)? == self.context,
            "PQ_PARENT_RECOVERY_CONTEXT",
        )
    }
    pub fn context_id(&self) -> Hash {
        self.context
    }
    pub fn history_transport(&self) -> &'static str {
        PQ_RECOVERY_HISTORY_TRANSPORT
    }
    pub fn policy(&self) -> &PqNetworkPolicy {
        self.transport.client().policy()
    }
    pub fn peer_key_id(&self) -> Hash {
        self.transport.client().peer_key_id()
    }
    /// Decode packet identity using the selected Node's actual wire profile,
    /// including NPQ6. This is data identity, not admission or current authority.
    pub fn packet_id(&self, request: &Request) -> Result<Option<Hash>> {
        match request {
            Request::Submit { packet } => {
                let codec = self.packet_settings.packet_codec_context();
                crate::ingress::hex_packet_for_context(packet, &codec)?
                    .id()
                    .map(Some)
            }
            _ => Ok(None),
        }
    }
    pub fn prepare(
        &self,
        sequence: u64,
        expiry: u64,
        request: Request,
    ) -> Result<PreparedPqRequest> {
        self.transport.client().prepare(sequence, expiry, request)
    }
    pub fn restore_prepared(&self, wire: &[u8]) -> Result<PreparedPqRequest> {
        self.transport.client().restore_prepared(wire)
    }
    pub fn audit_retained_request(
        &self,
        wire: &[u8],
        request: &Request,
    ) -> Result<(u64, u64, Hash)> {
        self.transport
            .client()
            .audit_retained_request(wire, request)
    }
    /// The server signs the operation statement, not the randomized request
    /// signature bytes. This is historical evidence and never live permission.
    pub fn audit_retained_reply(&self, request: &[u8], reply: &[u8]) -> Result<()> {
        self.transport.client().audit_retained_reply(request, reply)
    }
    pub fn send_until(
        &self,
        request: &PreparedPqRequest,
        deadline: Instant,
    ) -> Result<PqResponseEvidence> {
        self.transport
            .send_until(self.native_address, request, deadline)
    }
    pub fn send(
        &self,
        request: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<PqResponseEvidence> {
        self.transport.send(self.native_address, request, budget)
    }
    /// Only the actual PQHistoryV4 Head/History path is reachable here.
    /// Its membership observation does not prove native sequence consumption
    /// or the native peer policy's current revocation frontier.
    pub fn read_history(
        &self,
        node: &Node,
        request: &HistoryRequest,
        deadline: Instant,
    ) -> (Result<PublicReply>, PublicClientMetrics) {
        let admitted = (|| {
            ensure(
                matches!(
                    request,
                    HistoryRequest::Head | HistoryRequest::History { .. }
                ),
                "PQ_PARENT_RECOVERY_HISTORY_READ_ONLY",
            )?;
            self.validate_for_node(node)?;
            ensure(Instant::now() < deadline, "SUBMIT_RECOVERY_DEADLINE")
        })();
        if let Err(error) = admitted {
            return (Err(error), PublicClientMetrics::default());
        }
        call_public_history_pq_v4(
            self.history_address,
            request,
            node.settings(),
            &self.server_spki,
            self.policy().server_key_id(),
            self.history_identity,
            self.history_policy,
            Some(deadline),
        )
    }
}

#[cfg(test)]
mod context_tests;

mod files;
mod journal;
mod recovery;
pub use recovery::{
    submit_with_pq_parent_recovery, NativeRecoveryAttempt, PendingRecovery, PqRecoveryAttempt,
    PqRecoveryCampaign, PqSubmitRecoveryOutcome,
};
