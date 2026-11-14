//! Explicit shared-owner listeners for native mutations paired with HistoryV4.
//! Both listeners must receive the same Arc; this layer creates no Node,
//! ledger, replay owner, execution pool or authentication fallback.
use super::*;

enum SharedServer {
    Plain(PqServer),
    #[cfg(feature = "pq-native-openssl")]
    Tls(tls::PqTlsServer),
}
impl SharedServer {
    fn policy(&self) -> &PqNetworkPolicy {
        match self {
            Self::Plain(server) => &server.policy,
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls(server) => server.selected_policy(),
        }
    }
    fn connection(
        &self,
        mut stream: TcpStream,
        node: &Mutex<Node>,
        deadline: Instant,
    ) -> Result<()> {
        match self {
            Self::Plain(server) => observe_operation!(
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
                        server.read_request(node, &mut stream, deadline)
                    )
                    .and_then(|wire| {
                        observe_phase!(observation, TcpHandle, server.handle(node, &wire, deadline))
                    })
                    .and_then(|response| {
                        observe_phase!(
                            observation,
                            TcpWriteFrame,
                            super::super::write_frame_deadline(&mut stream, &response, deadline)
                        )
                    })
                }
            ),
            #[cfg(feature = "pq-native-openssl")]
            Self::Tls(server) => server.connection(stream, node, deadline),
        }
    }
}

/// Native authenticated plaintext remains loopback-only. The shared Node is
/// checked before accepting traffic and again by the original admission path.
pub fn serve_pq_authenticated_shared(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: PqServer,
) -> Result<PqNetworkMetrics> {
    server.policy.require_plaintext()?;
    serve(listener, node, lifetime, stop, SharedServer::Plain(server))
}

/// The actual hybrid TLS channel retains its certificate, peer, metering and
/// transport-admission checks. This selection cannot enter the plaintext arm.
#[cfg(feature = "pq-native-openssl")]
pub fn serve_pq_tls13_shared(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: tls::PqTlsServer,
) -> Result<PqNetworkMetrics> {
    server.selected_policy().tls_pins()?;
    serve(listener, node, lifetime, stop, SharedServer::Tls(server))
}

fn serve(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    lifetime: Duration,
    stop: Arc<AtomicBool>,
    server: SharedServer,
) -> Result<PqNetworkMetrics> {
    // TLS endpoint selection checks the same exact target as the standalone
    // listener; plaintext and legacy TLS policies remain loopback-only.
    server
        .policy()
        .check_network_target(listener.local_addr()?)?;
    ensure(
        !lifetime.is_zero() && lifetime <= Duration::from_secs(3600),
        "PQ_NETWORK_SERVER_BUDGET",
    )?;
    // The startup lock consumes this same lifetime, rather than establishing
    // a fresh interval after another service releases the shared owner.
    let end = Instant::now() + lifetime;
    let startup = end.min(Instant::now() + Duration::from_secs(10));
    lock_live_owner(&node, startup, None)?.check_pq_network_policy(server.policy())?;
    check_live_request(startup, None)?;
    listener.set_nonblocking(true)?;
    let mut metrics = PqNetworkMetrics::default();
    let accept_limit = server
        .policy()
        .tls_endpoint_pins()
        .map(|_| TLS_ENDPOINT_ACCEPT_LIMIT);
    while !stop.load(Ordering::Acquire)
        && Instant::now() < end
        && accept_limit.is_none_or(|limit| metrics.accepted + metrics.refused < limit)
    {
        match listener.accept() {
            Ok((stream, _)) => {
                let deadline = end.min(Instant::now() + Duration::from_secs(10));
                if server.connection(stream, &node, deadline).is_ok() {
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
