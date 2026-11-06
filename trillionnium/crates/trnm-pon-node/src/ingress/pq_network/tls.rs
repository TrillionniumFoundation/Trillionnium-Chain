//! Explicit hybrid-TLS transport for the actual native PQ owner. This loopback
//! integration neither enables the public-history reactor nor declares private
//! task/WAN/PKI/custody/production qualification.
use super::*;
mod context;
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
        let mut channel = io::Channel::connect(stream, deadline, &self.context)?;
        channel.write_frame(wire)?;
        channel.read_frame()
    }
}

pub struct PqTlsServer {
    inner: PqServer,
    context: context::TlsContext,
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
        })
    }
    fn connection(&self, stream: TcpStream, node: &Mutex<Node>, deadline: Instant) -> Result<()> {
        self.inner.charge_connection(node, deadline)?;
        let mut channel =
            io::Channel::accept(stream, deadline, &self.context, node, &self.inner.policy)?;
        let wire = self
            .inner
            .read_request_body(node, deadline, &mut |bytes| channel.read_exact(bytes))?;
        let response = self
            .inner
            .handle_admitted(node, &wire, deadline, channel.admission())?;
        channel.write_frame(&response)
    }
}

/// Real Node listener, intentionally loopback only. TLS carries the same
/// bounded Request and enters the existing metered admission, replay, work
/// checking, execution and durable receipt path. No signature supplies work.
pub fn serve_pq_tls13(
    listener: TcpListener,
    node: Node,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PqTlsServer,
) -> Result<PqNetworkMetrics> {
    server.inner.policy.tls_pins()?;
    ensure(
        listener.local_addr()?.ip().is_loopback(),
        "PQ_NETWORK_LOOPBACK_ONLY",
    )?;
    ensure(
        !lifetime.is_zero() && lifetime <= Duration::from_secs(3600),
        "PQ_NETWORK_SERVER_BUDGET",
    )?;
    node.check_pq_network_policy(&server.inner.policy)?;
    listener.set_nonblocking(true)?;
    let owner = Mutex::new(node);
    let end = Instant::now() + lifetime;
    let mut metrics = PqNetworkMetrics::default();
    while !stop.load(Ordering::Acquire) && Instant::now() < end {
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

