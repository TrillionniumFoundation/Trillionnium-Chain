//! Explicit hybrid-TLS transport for the actual native PQ owner. This loopback
//! integration neither enables the public-history reactor nor declares private
//! task/WAN/PKI/custody/production qualification.
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
    pub(crate) fn selected_client(&self) -> &PqClient {
        &self.inner
    }
    pub fn restore_prepared(&self, wire: &[u8]) -> Result<PreparedPqRequest> {
        self.inner.restore_prepared(wire)
    }
    pub fn audit_retained_reply(&self, request_wire: &[u8], reply_wire: &[u8]) -> Result<()> {
        self.inner.audit_retained_reply(request_wire, reply_wire)
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
        self.send_with_evidence(address, prepared, budget)
            .map(PqResponseEvidence::into_response)
    }
    pub fn send_with_evidence(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<PqResponseEvidence> {
        self.inner.policy.tls_pins()?;
        self.inner.check_send(address, prepared, budget)?;
        let end = Instant::now() + budget;
        let wire = self.exchange(address, prepared.wire(), end)?;
        let response = self.inner.finish_response(&wire, prepared, end)?;
        Ok(PqResponseEvidence { response, wire })
    }
    pub fn send_verified(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        budget: Duration,
    ) -> Result<VerifiedPqReply> {
        self.inner.policy.tls_pins()?;
        self.inner.check_send(address, prepared, budget)?;
        self.send_verified_until(address, prepared, Instant::now() + budget)
    }
    pub(super) fn send_verified_until(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        deadline: Instant,
    ) -> Result<VerifiedPqReply> {
        let evidence = self.send_with_evidence_until(address, prepared, deadline)?;
        self.inner.seal_verified_reply(evidence, prepared, deadline)
    }
    /// Use the original absolute deadline for the real TLS exchange.
    /// Validation, handshake and receipt verification cannot renew it.
    pub fn send_with_evidence_until(
        &self,
        address: SocketAddr,
        prepared: &PreparedPqRequest,
        deadline: Instant,
    ) -> Result<PqResponseEvidence> {
        self.inner.policy.tls_pins()?;
        self.inner.check_send_until(address, prepared, deadline)?;
        let wire = self.exchange(address, prepared.wire(), deadline)?;
        let response = self
            .inner
            .finish_response_until(&wire, prepared, deadline)?;
        Ok(PqResponseEvidence { response, wire })
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
    pub(super) fn selected_policy(&self) -> &PqNetworkPolicy {
        &self.inner.policy
    }
    pub(super) fn connection(
        &self,
        stream: TcpStream,
        node: &Mutex<Node>,
        deadline: Instant,
    ) -> Result<()> {
        let observation = diagnostics::Observation::new();
        let result = (|| {
            observation.stage("ingress_admission");
            self.inner.charge_connection(node, deadline)?;
            observation.stage("tls_handshake");
            let mut channel = io::Channel::accept_observed(
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

#[cfg(test)]
mod tests;
