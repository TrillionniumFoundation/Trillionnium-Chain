//! Finite, real loopback UDP discovery -> explicit TCP selection -> TCV2 readback.
//!
//! Synthetic F32-shaped bytes and a data-only environment record are not a
//! usable model. Owner pins precede all discovery. This exercises no inference,
//! CURRENT, FinalUse, private-weight protection, independent custody or WAN.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs, io,
    net::{SocketAddr, SocketAddrV4, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_data_availability::cell::{
    fetch_cell_bep52_with_content, lookup_cell_bep52_dht_peers, CellBep52BindingV1,
    CellBep52DhtEndpointPolicyV1, CellBep52DhtLookupStopV1, CellBep52PeerLimitsV1,
    CellBep52PeerSessionV1, CellBep52PeerUsageV1, CellBep52SeedV1, CellCacheConfigV4,
    CellClosureFileV1, CellContentReadSessionV2, CellContextV1, CellErrorV1, CellFileRoleV1,
    CellLoaderContextV1, CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1,
    CellReleaseLimitsV1, CellResultV1, CellStoreV1, CellVersionContentV2,
    CellVersionLoaderContextV1, CellVersionManifestV1, CELL_BEP52_PIECE_BYTES_V1,
};

const WINDOW: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);
const NODE: [u8; 20] = [193; 20];

fn require(condition: bool, reason: &'static str) -> CellResultV1<()> {
    if condition {
        Ok(())
    } else {
        Err(CellErrorV1::Invalid(reason))
    }
}

fn cache() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 << 20,
        max_logical_bytes: 1 << 20,
        max_chunk_rows: 16,
        max_manifest_rows: 4,
    }
}

fn limits(deadline: Instant, attempts: u64) -> CellBep52PeerLimitsV1 {
    CellBep52PeerLimitsV1 {
        deadline,
        request_timeout: Duration::from_secs(2),
        max_connections: attempts,
        max_received_bytes: 1 << 20,
        max_sent_bytes: 1 << 20,
        max_messages: 128,
    }
}

fn read_limits(version: &CellVersionManifestV1, deadline: Instant) -> CellReleaseLimitsV1 {
    CellReleaseLimitsV1 {
        max_payload_bytes: version.manifests().iter().map(CellManifestV1::size).sum(),
        max_chunks: version
            .manifests()
            .iter()
            .map(|m| m.chunks().len() as u64)
            .sum(),
        deadline,
    }
}

fn owner(closure: &CellReleaseClosureV1, role: CellFileRoleV1) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![role],
        max_payload_bytes: 1 << 20,
        max_chunks: 16,
    }
}

fn pack(
    store: &CellStoreV1,
    path: &Path,
    bytes: &[u8],
    context: CellContextV1,
) -> CellResultV1<CellManifestV1> {
    fs::write(path, bytes)?;
    store.pack_file(path, context, CELL_BEP52_PIECE_BYTES_V1)
}

fn file(path: &str, role: CellFileRoleV1, manifest: &CellManifestV1) -> CellClosureFileV1 {
    CellClosureFileV1 {
        path: path.into(),
        role,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies: vec![],
    }
}

fn fixture(directory: &Path, deadline: Instant) -> CellResultV1<(PathBuf, CellVersionContentV2)> {
    let path = directory.join("source.sqlite");
    let store = CellStoreV1::open(&path, cache())?;
    let context = CellContextV1 {
        family: "iterative-discovery-synthetic-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let config = pack(
        &store,
        &directory.join("environment.json"),
        br#"{"runtime":"synthetic-weight-observer-v1","loader":"bytes-only"}"#,
        context.clone(),
    )?;
    let environment = CellReleaseClosureV1::new(
        context.clone(),
        1,
        [6; 32],
        vec![0],
        vec![file(
            "environment.json",
            CellFileRoleV1::Configuration,
            &config,
        )],
    )?;
    let weights: Vec<u8> = (0..8193)
        .flat_map(|i| ((i % 257) as f32 / 128.0 - 1.0).to_le_bytes())
        .collect();
    let model_context = CellContextV1 {
        runtime: environment.id(),
        ..context
    };
    let base = pack(
        &store,
        &directory.join("weights.f32le"),
        &weights,
        model_context.clone(),
    )?;
    let model = CellModelReleaseRootV1::new(
        CellReleaseClosureV1::new(
            model_context,
            2,
            [7; 32],
            vec![0],
            vec![file("weights.f32le", CellFileRoleV1::Base, &base)],
        )?,
        vec![],
    )?;
    let mut manifests = vec![base, config];
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(model, environment, manifests)?;
    let model_owner = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment_owner = owner(version.environment(), CellFileRoleV1::Configuration);
    let expected = CellVersionLoaderContextV1 {
        commitment: version.commitment(),
        model: &model_owner,
        environment: &environment_owner,
    };
    let mut capture = CellContentReadSessionV2::new(read_limits(&version, deadline), 1)?;
    let content = CellVersionContentV2::capture_cached(&version, &store, &expected, &mut capture)?;
    Ok((path, content))
}

struct Worker<T> {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<T>>>,
}

impl<T: Send + 'static> Worker<T> {
    fn spawn(
        stop: Arc<AtomicBool>,
        task: impl FnOnce() -> CellResultV1<T> + Send + 'static,
    ) -> CellResultV1<Self> {
        Ok(Self {
            stop,
            handle: Some(thread::Builder::new().spawn(task)?),
        })
    }

    fn finish(mut self) -> CellResultV1<T> {
        self.handle
            .take()
            .ok_or(CellErrorV1::Invalid("observer worker already joined"))?
            .join()
            .map_err(|_| CellErrorV1::Invalid("observer worker panic"))?
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn active(stop: &AtomicBool, deadline: Instant) -> CellResultV1<()> {
    require(!stop.load(Ordering::Acquire), "observer cancelled")?;
    require(Instant::now() < deadline, "observer original deadline")
}

fn ipv4(address: SocketAddr) -> CellResultV1<SocketAddrV4> {
    match address {
        SocketAddr::V4(value) => Ok(value),
        _ => Err(CellErrorV1::Invalid("observer IPv4 only")),
    }
}

fn compact(endpoint: SocketAddrV4) -> [u8; 6] {
    let mut bytes = [0; 6];
    bytes[..4].copy_from_slice(&endpoint.ip().octets());
    bytes[4..].copy_from_slice(&endpoint.port().to_be_bytes());
    bytes
}

// These small fixture encoders are independent of the production bencode parser.
fn query(binding: &CellBep52BindingV1, transaction: [u8; 8]) -> Vec<u8> {
    let mut bytes = b"d1:ad2:id20:".to_vec();
    bytes.extend(NODE);
    bytes.extend(b"9:info_hash20:");
    bytes.extend(&binding.info_hash()[..20]);
    bytes.extend(b"e1:q9:get_peers2:roi1e1:t8:");
    bytes.extend(transaction);
    bytes.extend(b"1:y1:qe");
    bytes
}

fn response(transaction: [u8; 8], second: SocketAddrV4, peer: Option<SocketAddrV4>) -> Vec<u8> {
    let mut bytes = b"d1:rd2:id20:".to_vec();
    bytes.extend(if peer.is_some() { [12; 20] } else { [11; 20] });
    match peer {
        Some(peer) => {
            bytes.extend(b"5:nodes0:5:token1:t6:valuesl6:");
            bytes.extend(compact(peer));
        }
        None => {
            bytes.extend(b"5:nodes26:");
            bytes.extend([12; 20]);
            bytes.extend(compact(second));
            bytes.extend(b"5:token1:t6:valuesl");
        }
    }
    bytes.extend(b"ee1:t8:");
    bytes.extend(transaction);
    bytes.extend(b"1:y1:re");
    bytes
}

fn dht(
    socket: UdpSocket,
    requests: Vec<(Vec<u8>, Vec<u8>)>,
    deadline: Instant,
) -> CellResultV1<Worker<(u64, u64)>> {
    socket.set_read_timeout(Some(POLL))?;
    socket.set_write_timeout(Some(POLL))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    Worker::spawn(stop, move || {
        let mut totals = (0, 0);
        let mut packet = [0; 1200];
        for (expected, response) in requests {
            let (received, caller) = loop {
                active(&stopped, deadline)?;
                match socket.recv_from(&mut packet) {
                    Ok(value) => break value,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            require(
                packet[..received] == expected,
                "observer exact get_peers/read-only query",
            )?;
            active(&stopped, deadline)?;
            let sent = socket.send_to(&response, caller)?;
            require(sent == response.len(), "observer UDP partial reply")?;
            totals.0 += received as u64;
            totals.1 += sent as u64;
        }
        Ok(totals)
    })
}

fn seed(
    listener: TcpListener,
    path: PathBuf,
    binding: CellBep52BindingV1,
    deadline: Instant,
) -> CellResultV1<Worker<CellBep52PeerUsageV1>> {
    listener.set_nonblocking(true)?;
    let mut budget = CellBep52PeerSessionV1::new([92; 32], limits(deadline, 1))?;
    let stop = budget.cancellation_handle();
    let stopped = Arc::clone(&stop);
    Worker::spawn(stop, move || {
        let store = CellStoreV1::open_read_only(&path)?;
        let seed = CellBep52SeedV1::prepare(&store, &binding, deadline)?;
        let stream = loop {
            active(&stopped, deadline)?;
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error) => return Err(error.into()),
            }
        };
        seed.serve_connection(stream, [93; 20], &mut budget)?;
        Ok(budget.usage().clone())
    })
}

fn usage(value: &CellBep52PeerUsageV1) -> Value {
    json!({"dht_queries": value.dht_query_attempts, "tcp_attempts": value.connection_attempts,
        "sent_bytes": value.sent_bytes, "received_bytes": value.received_bytes,
        "sent_messages": value.sent_messages, "received_messages": value.received_messages,
        "refused_queries": value.refused_dht_queries, "refused_connections": value.refused_connections,
        "completed_fetches": value.completed_fetches})
}

fn observe() -> CellResultV1<Value> {
    let started = Instant::now();
    let deadline = started + WINDOW;
    let directory = tempfile::tempdir()?;
    let (source, captured) = fixture(directory.path(), deadline)?;
    // This trusted local owner freezes exact metadata/content before any lookup.
    let content_pin = captured.commitment();
    let version_pin = captured.version().commitment();
    let content = CellVersionContentV2::decode(&captured.encode())?;
    let model_owner = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment_owner = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let expected = CellVersionLoaderContextV1 {
        commitment: version_pin,
        model: &model_owner,
        environment: &environment_owner,
    };
    let pinned = content.pin_for_owner(&expected, content_pin)?;
    let read_limits = read_limits(content.version(), deadline);
    let mut read_budget = CellContentReadSessionV2::new(read_limits, 1)?;
    let mut session = CellBep52PeerSessionV1::new([91; 32], limits(deadline, 6))?;
    let consumer = CellStoreV1::open(&directory.path().join("receiver.sqlite"), cache())?;
    let bindings: Vec<_> = content
        .version()
        .manifests()
        .iter()
        .map(|manifest| {
            CellBep52BindingV1::from_pinned_manifest(manifest, manifest.id(), manifest.context())
        })
        .collect::<CellResultV1<_>>()?;
    let mut peers = Vec::new();
    for _ in &bindings {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        peers.push((ipv4(listener.local_addr()?)?, listener));
    }
    let first = UdpSocket::bind("127.0.0.1:0")?;
    let second = UdpSocket::bind("127.0.0.1:0")?;
    let a = ipv4(first.local_addr()?)?;
    let b = ipv4(second.local_addr()?)?;
    let endpoints: Vec<_> = [a, b]
        .into_iter()
        .chain(peers.iter().map(|p| p.0))
        // TCP and UDP may validly share an ephemeral numeric endpoint.
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let policy = CellBep52DhtEndpointPolicyV1::explicit(&endpoints)?;
    let mut transactions = [[0; 8]; 4];
    for id in &mut transactions {
        getrandom::getrandom(id).map_err(|_| CellErrorV1::Invalid("observer entropy"))?;
    }
    require(
        transactions.iter().all(|id| *id != [0; 8]),
        "observer nonzero transaction",
    )?;
    for i in 0..transactions.len() {
        require(
            !transactions[..i].contains(&transactions[i]),
            "observer unique transaction",
        )?;
    }
    let first_requests = bindings
        .iter()
        .enumerate()
        .map(|(i, binding)| {
            (
                query(binding, transactions[2 * i]),
                response(transactions[2 * i], b, None),
            )
        })
        .collect();
    let second_requests = bindings
        .iter()
        .enumerate()
        .map(|(i, binding)| {
            (
                query(binding, transactions[2 * i + 1]),
                response(transactions[2 * i + 1], b, Some(peers[i].0)),
            )
        })
        .collect();
    let first_worker = dht(first, first_requests, deadline)?;
    let second_worker = dht(second, second_requests, deadline)?;
    let mut rows = Vec::new();
    let mut tcp_received = 0;
    let mut tcp_sent = 0;
    for (i, (binding, (peer, listener))) in bindings.iter().zip(peers).enumerate() {
        let before = session.usage().connection_attempts;
        let discovered = lookup_cell_bep52_dht_peers(
            binding,
            &[a],
            NODE,
            &transactions[2 * i..2 * i + 2],
            &policy,
            &mut session,
        )?;
        require(
            discovered.queried_endpoints == [a, b]
                && discovered.successful_queries == 2
                && discovered.peer_candidates == [peer]
                && discovered.stop == CellBep52DhtLookupStopV1::FrontierExhausted
                && discovered.rejected_candidates == 0
                && discovered.duplicate_candidates == 0,
            "observer exact two-hop discovery",
        )?;
        require(
            session.usage().connection_attempts == before
                && matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "observer discovery must not dial TCP",
        )?;
        // The owner compares the hint with its explicit allowed endpoint before
        // handing it to the existing fetch API. DHT itself performs no TCP dial.
        let approved = [SocketAddr::V4(peer)];
        let provider = seed(listener, source.clone(), binding.clone(), deadline)?;
        let fetched = fetch_cell_bep52_with_content(
            &consumer,
            binding,
            &pinned,
            &approved,
            [94; 20],
            &mut session,
        )?;
        let served = provider.finish()?;
        tcp_received += served.received_bytes;
        tcp_sent += served.sent_bytes;
        require(
            fetched.cached_chunks == 0
                && fetched.downloaded_chunks == binding.manifest().chunks().len()
                && fetched.downloaded_bytes == binding.manifest().size(),
            "observer complete cold fetch",
        )?;
        rows.push(json!({"manifest": hex::encode(binding.manifest().id()), "info_hash": hex::encode(binding.info_hash()),
            "dht_queries": discovered.queried_endpoints.len(), "owner_selected_peers": 1,
            "downloaded_chunks": fetched.downloaded_chunks, "downloaded_bytes": fetched.downloaded_bytes,
            "cached_chunks": fetched.cached_chunks, "provider_usage": usage(&served)}));
    }
    let a_bytes = first_worker.finish()?;
    let b_bytes = second_worker.finish()?;
    let cancellation = session.cancellation_handle();
    let verified = content.verify_cached_controlled(
        &consumer,
        &expected,
        content_pin,
        &mut read_budget,
        &mut || active(&cancellation, deadline),
    )?;
    require(
        verified.content().commitment() == content_pin
            && session.deadline() == deadline
            && read_budget.deadline() == deadline,
        "observer unchanged content/deadline",
    )?;
    let used = session.usage();
    require(
        used.dht_query_attempts == 4
            && used.connection_attempts == 2
            && used.completed_fetches == 2
            && used.refused_connections == 0
            && used.refused_dht_queries == 0
            && used.sent_bytes == a_bytes.0 + b_bytes.0 + tcp_received
            && used.received_bytes == a_bytes.1 + b_bytes.1 + tcp_sent,
        "observer exact wire accounting",
    )?;
    let read = read_budget.usage();
    require(
        read.attempted_scans == 1
            && read.reserved_payload_bytes == read_limits.max_payload_bytes
            && read.reserved_chunks == read_limits.max_chunks,
        "observer exact complete readback",
    )?;
    Ok(
        json!({"schema": "trnm.cell-bep52-iterative-discovery-observation.v1", "status": "PASS_LOCAL_OBSERVATION",
        "qualification": "HOLD_NO_GO", "synthetic": true, "loopback_only": true,
        "content_pin_frozen_before_discovery": hex::encode(content_pin), "version_pin": hex::encode(version_pin),
        "single_receiver_transport_session": true, "operation_window_ms": WINDOW.as_millis(),
        "shared_original_absolute_deadline": true,
        "transport_limits": {"total_udp_tcp_attempts": 6, "received_bytes": 1 << 20, "sent_bytes": 1 << 20, "messages": 128},
        "receiver_usage": usage(used), "full_content_readback": {"attempts": read.attempted_scans,
            "reserved_payload_bytes": read.reserved_payload_bytes, "reserved_chunks": read.reserved_chunks},
        "readback_budget_scope": "one pre-admitted full receiver scan; publisher capture is a separate one-scan source reservation",
        "wire_byte_accounting": "actual UDP/TCP application bytes; receiver totals equal all fixture-server reverse totals; no IP overhead",
        "provider_threads_joined": 4, "observations": rows, "wall_ns": started.elapsed().as_nanos(),
        "example_source_sha256": hex::encode(Sha256::digest(include_bytes!("cell_bep52_iterative_discovery.rs"))),
        "hepta_final_use": false, "model_forward": false, "independent_custody": false,
        "wan_qualified": false, "production_activation": false, "private_weight_transport": false}),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    match observe() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(error) => {
            println!(
                "{}",
                json!({"schema": "trnm.cell-bep52-iterative-discovery-observation.v1",
                "status": "FAILED_OBSERVATION", "qualification": "HOLD_NO_GO", "error": error.to_string(),
                "hepta_final_use": false, "production_activation": false})
            );
            return Err(error.into());
        }
    }
    Ok(())
}
