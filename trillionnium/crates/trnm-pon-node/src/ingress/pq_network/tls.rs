//! Explicit hybrid-TLS transport for the actual native PQ owner. The original
//! loopback profile and the separately pinned endpoint development profile do
//! not enable the public-history reactor or qualify WAN/PKI/custody/production.
use super::*;
mod context;
mod diagnostics;
mod io;
pub use context::PqTlsIdentity;

pub struct PqTlsClient {
    inner: PqClient,
    context: context::TlsContext,
}
impl PqTlsClient {
    pub fn new(
        policy: Arc<PqNetworkPolicy>,
        signer: PqNativeSigningKey,
        identity: PqTlsIdentity,
    ) -> Result<Self> {
        let context =
            context::TlsContext::new(policy.clone(), signer.public_key_id(), identity, false)?;
        Ok(Self {
            inner: PqClient::new(policy, signer)?,
            context,
        })
    }
    pub fn prepare(
        &self,
        sequence: u64,
        expires_at: u64,
        request: Request,
    ) -> Result<PreparedPqRequest> {
        self.inner.prepare(sequence, expires_at, request)
    }
    pub fn send(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<PqResponse> {
        self.inner.policy.tls_pins()?;
        self.inner.check_send(address, prepared, budget)?;
        let end = Instant::now() + budget;
        let response = self.exchange(address, prepared.wire(), end)?;
        self.inner.finish_response(&response, prepared, end)
    }
    fn exchange(&self, address: SocketAddr, wire: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        let budget = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("PQ_NETWORK_DEADLINE")?;
        let stream = TcpStream::connect_timeout(&address, budget)?;
        self.inner
            .policy
            .check_tls_client_ip(stream.local_addr()?)?;
        let mut channel = io::Channel::connect(stream, deadline, &self.context)?;
        channel.write_frame(wire)?;
        channel.read_frame()
    }
}

pub struct PqTlsServer {
    inner: PqServer,
    context: context::TlsContext,
    refusal_records: std::sync::atomic::AtomicUsize,
}
impl PqTlsServer {
    pub fn new(
        policy: Arc<PqNetworkPolicy>,
        signer: PqNativeSigningKey,
        identity: PqTlsIdentity,
    ) -> Result<Self> {
        let context =
            context::TlsContext::new(policy.clone(), signer.public_key_id(), identity, true)?;
        Ok(Self {
            inner: PqServer::new(policy, signer)?,
            context,
            refusal_records: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    fn connection(&self, stream: TcpStream, node: &Mutex<Node>, deadline: Instant) -> Result<()> {
        let observation = diagnostics::Observation::new();
        let result = (|| {
            // The actual kernel peer address is checked before any Node/witness
            // observation or handshake debit. An IP pin grants no signer authority.
            self.inner.policy.check_tls_client_ip(stream.peer_addr()?)?;
            observation.stage("ingress_admission");
            self.inner.charge_connection(node, deadline)?;
            observation.stage("tls_handshake");
            let mut channel = io::Channel::accept(
                stream,
                deadline,
                &self.context,
                node,
                &self.inner.policy,
                &observation,
            )?;
            observation.stage("request_read");
            let wire = self
                .inner
                .read_request_body(node, deadline, &mut |bytes| channel.read_exact(bytes))?;
            observation.stage("request_dispatch");
            let response =
                self.inner
                    .handle_admitted(node, &wire, deadline, channel.admission())?;
            observation.stage("response_write");
            channel.write_frame(&response)
        })();
        if let Err(error) = &result {
            observation.emit(error, deadline, &self.refusal_records);
        }
        result
    }
}

/// Real Node listener. Existing profiles remain loopback-only; the explicit
/// endpoint profile binds one exact address and requires the witness backend.
/// Both enter the same metered admission, replay, work and durable receipt path.
pub fn serve_pq_tls13(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PqTlsServer,
) -> Result<PqNetworkMetrics> {
    server.inner.policy.tls_pins()?;
    server
        .inner
        .policy
        .check_tls_listener(listener.local_addr()?)?;
    ensure(
        !lifetime.is_zero() && lifetime <= Duration::from_secs(3600),
        "PQ_NETWORK_SERVER_BUDGET",
    )?;
    node.check_pq_network_policy(&server.inner.policy)?;
    listener.set_nonblocking(true)?;
    let owner = Mutex::new(node);
    let end = Instant::now() + lifetime;
    let mut metrics = PqNetworkMetrics::default();
    let accept_limit = server
        .inner
        .policy
        .tls_endpoint_pins()
        .map(|_| TLS_ENDPOINT_ACCEPT_LIMIT);
    while !stop.load(Ordering::Acquire)
        && Instant::now() < end
        && accept_limit.is_none_or(|limit| metrics.accepted + metrics.refused < limit)
    {
        match listener.accept() {
            Ok((stream, _)) => {
                let deadline = end.min(Instant::now() + Duration::from_secs(10));
                let result = server.connection(stream, &owner, deadline);
                if result.is_ok() {
                    metrics.accepted += 1;
                } else {
                    metrics.refused += 1;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(metrics)
}

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod endpoint_tests;
