//! Explicit client wiring for the independently retained PNQ2 witness.
//! This creates no witness state and supplies no whole-node rollback authority.
use super::{ensure, input, spki};
use openssl::pkey::PKey;
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde::Deserialize;
use std::{os::unix::net::UnixStream, path::Path, time::Instant};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_pon_node::{
    ingress::pq_network::PqNetworkPolicy,
    pq_rollback_witness::{ConnectedWitnessTransport, WitnessBinding, WitnessClient, MAX_EXCHANGE},
    Node, Result, Settings,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    generation: u64,
    witness_spki: String,
    writer_spki: String,
    socket: String,
    node_mode: NodeMode,
}

// Missing is the legacy schema. A present null is still an invalid new field,
// never a way to make the legacy schema accept an unknown witness selection.
pub(super) fn present_configuration<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Configuration>, D::Error> {
    Configuration::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NodeMode {
    Create,
    OpenExisting,
    // Only the new ordinary local entry selects this private stricter mode.
    // It is not a new accepted spelling in the original v2 configuration.
    #[serde(skip)]
    OpenInitialized,
}

impl Configuration {
    pub(super) fn require_existing_node(&self) -> Result<()> {
        ensure(
            matches!(self.node_mode, NodeMode::OpenExisting),
            "PQ_APPLICATION_EXISTING_OWNER_REQUIRED",
        )
    }

    pub(super) fn open_initialized_node(
        mut self,
        store: &Path,
        settings: Settings,
        workers: usize,
        policy: &PqNetworkPolicy,
        key_path: &str,
    ) -> Result<Node> {
        self.require_existing_node()?;
        self.node_mode = NodeMode::OpenInitialized;
        self.open_node(store, settings, workers, policy, key_path)
    }

    pub(super) fn open_node(
        self,
        store: &Path,
        settings: Settings,
        workers: usize,
        policy: &PqNetworkPolicy,
        key_path: &str,
    ) -> Result<Node> {
        // Selection is part of the pinned configuration, never inferred from
        // missing files or a failed existing-state/witness observation.
        match self.node_mode {
            NodeMode::OpenInitialized => ensure(
                store.join("native.sqlite").is_file(),
                "PQ_WITNESS_EXISTING_NODE_REQUIRED",
            )?,
            NodeMode::Create => ensure(
                !store.join("native.sqlite").exists(),
                "PQ_WITNESS_NEW_NODE_REQUIRED",
            )?,
            NodeMode::OpenExisting => ensure(
                store.join("native.sqlite").is_file(),
                "PQ_WITNESS_EXISTING_NODE_REQUIRED",
            )?,
        }
        let witness_spki = spki(&self.witness_spki)?;
        let writer_spki = spki(&self.writer_spki)?;
        let binding = WitnessBinding::new(policy, self.generation, &witness_spki, &writer_spki)?;
        let writer_id =
            ml_dsa_65_key_id_from_spki(&writer_spki).map_err(|_| "PQ_TLS_WITNESS_WRITER_PIN")?;
        let bytes = input(key_path, 32_768, true)?;
        let key = PKey::private_key_from_pem(&bytes).map_err(|_| "PQ_TLS_WITNESS_LOCAL_KEY")?;
        let writer = PqNativeSigningKey::from_owned_key(key, writer_id)
            .map_err(|_| "PQ_TLS_WITNESS_LOCAL_KEY")?;
        let path = Path::new(&self.socket);
        ensure(path.is_absolute(), "PQ_TLS_WITNESS_SOCKET")?;
        let address = SocketAddrUnix::new(path).map_err(|_| "PQ_TLS_WITNESS_SOCKET")?;
        // A nonblocking Unix connect either completes immediately or refuses.
        // In-progress/backlog-full results are not retried and never cause a
        // blocking connect or an unjoined connection worker. Original Current
        // and CAS retain their own MAX_EXCHANGE bounds and uncertainty fences.
        let until = Instant::now() + MAX_EXCHANGE;
        #[cfg(not(target_vendor = "apple"))]
        let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
        #[cfg(target_vendor = "apple")]
        let flags = SocketFlags::empty();
        let descriptor = socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None)
            .map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
        #[cfg(target_vendor = "apple")]
        {
            // Apple has no SOCK_CLOEXEC/SOCK_NONBLOCK flags. The descriptor
            // remains private and unconnected until both safe fcntl calls pass.
            let fd_flags =
                rustix::io::fcntl_getfd(&descriptor).map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
            rustix::io::fcntl_setfd(&descriptor, fd_flags | rustix::io::FdFlags::CLOEXEC)
                .map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
            let status =
                rustix::fs::fcntl_getfl(&descriptor).map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
            rustix::fs::fcntl_setfl(&descriptor, status | rustix::fs::OFlags::NONBLOCK)
                .map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
        }
        ensure(Instant::now() < until, "PQ_TLS_WITNESS_CONNECT_TIMEOUT")?;
        connect(&descriptor, &address).map_err(|_| "PQ_TLS_WITNESS_CONNECT")?;
        ensure(Instant::now() < until, "PQ_TLS_WITNESS_CONNECT_TIMEOUT")?;
        let transport = ConnectedWitnessTransport::new(UnixStream::from(descriptor));
        let client = WitnessClient::new(binding, writer, Box::new(transport))?;
        match self.node_mode {
            NodeMode::OpenInitialized => {
                Node::open_existing_with_pq_witness(store, settings, workers, policy, client)
            }
            NodeMode::Create => {
                Node::create_with_pq_witness(store, settings, workers, policy, client)
            }
            NodeMode::OpenExisting => {
                Node::open_with_pq_witness(store, settings, workers, policy, client)
            }
        }
    }
}
