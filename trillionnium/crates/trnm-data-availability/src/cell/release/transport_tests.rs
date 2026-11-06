//! Complete release operations share their original transport reservation.
//! Real TCP fixtures exercise every marker profile; no marker authorizes use.

mod rarest;

use super::*;
use crate::cell::{
    serve_cells_bounded_with_availability, serve_cells_persistent, CellCacheConfigV4,
    CellClosureFileV1, CellContextV1, CellFileRoleV1, CellManifestV1, CellPersistentServeLimitsV2,
    CellPersistentServeReportV2, CellServeLimitsV1, CellTensorContractV1, CellTensorDTypeV1,
    CellTensorFileV1, CellTensorSpecV1,
};
use std::{
    net::TcpListener,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 2 * 1_048_576,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 16,
        max_manifest_rows: 16,
    }
}

#[derive(Clone, Copy, Debug)]
enum Marker {
    Release,
    Closure,
    Model,
    Tensor,
}

const MARKERS: [Marker; 4] = [
    Marker::Release,
    Marker::Closure,
    Marker::Model,
    Marker::Tensor,
];

struct Fixture {
    directory: tempfile::TempDir,
    origin_path: PathBuf,
    members: Vec<CellManifestV1>,
    model: CellTensorModelManifestV1,
    expected: CellLoaderContextV1,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let origin_path = directory.path().join("origin.sqlite");
        let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
        let context = CellContextV1 {
            family: "release-persistent-v2".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        };
        let mut header =
            br#"{"weights":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#.to_vec();
        header.resize(header.len().next_multiple_of(8), b' ');
        let tensor = [
            (header.len() as u64).to_le_bytes().as_slice(),
            &header,
            1.0f32.to_le_bytes().as_slice(),
            2.0f32.to_le_bytes().as_slice(),
        ]
        .concat();
        let mut members = Vec::new();
        let files = [
            ("base.safetensors", CellFileRoleV1::Base, tensor),
            (
                "tokenizer.json",
                CellFileRoleV1::Tokenizer,
                br#"{"version":"test-1","vocab":["a","b"]}"#.to_vec(),
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (name, role, bytes))| {
            let input = directory.path().join(name);
            fs::write(&input, bytes).unwrap();
            let manifest = origin.pack_file(&input, context.clone(), 16_384).unwrap();
            assert_eq!(manifest.chunks().len(), 1);
            let file = CellClosureFileV1 {
                path: name.into(),
                role,
                manifest: manifest.id(),
                payload_sha256: manifest.payload_sha256(),
                payload_bytes: manifest.size(),
                dependencies: if index == 0 { vec![1] } else { vec![] },
            };
            members.push(manifest);
            file
        })
        .collect();
        members.sort_by_key(CellManifestV1::id);
        let closure = CellReleaseClosureV1::new(context, 7, [6; 32], vec![0], files).unwrap();
        let expected = CellLoaderContextV1 {
            closure_id: closure.id(),
            context: closure.release().context().clone(),
            selected_generation: closure.selected_generation(),
            loader_profile: closure.loader_profile(),
            required_roles: vec![CellFileRoleV1::Base, CellFileRoleV1::Tokenizer],
            max_payload_bytes: 1_048_576,
            max_chunks: 16,
        };
        let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
        let contract = CellTensorContractV1::new(
            root.id(),
            vec![CellTensorFileV1 {
                file_index: 0,
                tensors: vec![CellTensorSpecV1 {
                    name: "weights".into(),
                    dtype: CellTensorDTypeV1::F32,
                    shape: vec![2],
                }],
            }],
        )
        .unwrap();
        let model = CellTensorModelManifestV1::new(root, contract).unwrap();
        Self {
            directory,
            origin_path,
            members,
            model,
            expected,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn cache(&self, name: &str) -> CellStoreV1 {
        CellStoreV1::open(&self.path(name), cache_config()).unwrap()
    }

    fn response_bytes(&self) -> u64 {
        self.members
            .iter()
            .map(|m| m.encode().len() as u64 + m.size() + 18)
            .sum()
    }

    fn wire(&self, marker: Marker) -> Vec<u8> {
        let root = self.model.root();
        match marker {
            Marker::Release => root.closure().release().encode(),
            Marker::Closure => root.closure().encode(),
            Marker::Model => root.encode(),
            Marker::Tensor => self.model.encode(),
        }
    }

    fn fetch(
        &self,
        marker: Marker,
        receiver: &CellStoreV1,
        peers: &[SocketAddr],
        options: CellReleaseFetchOptionsV2,
        output: &Path,
    ) -> CellResultV1<CellTransportFetchReportV2<CellReleaseFetchReportV1>> {
        let root = self.model.root();
        let closure = root.closure();
        let release = closure.release();
        match marker {
            Marker::Release => fetch_release_with_options_to_file(
                receiver,
                release,
                release.id(),
                peers,
                options,
                output,
            ),
            Marker::Closure => fetch_closure_with_options_to_file(
                receiver,
                closure,
                &self.expected,
                peers,
                options,
                output,
            )
            .map(|r| CellTransportFetchReportV2 {
                request_attempts: r.request_attempts,
                report: r.report.release,
            }),
            Marker::Model => fetch_model_release_with_options_to_file(
                receiver,
                root,
                (root.id(), &self.expected),
                peers,
                options,
                output,
            )
            .map(|r| CellTransportFetchReportV2 {
                request_attempts: r.request_attempts,
                report: r.report.release,
            }),
            Marker::Tensor => fetch_tensor_model_with_options_to_file(
                receiver,
                &self.model,
                (self.model.id(), &self.expected),
                peers,
                options,
                output,
            )
            .map(|r| CellTransportFetchReportV2 {
                request_attempts: r.request_attempts,
                report: r.report.release,
            }),
        }
    }
}

fn options(requests: u64, response_bytes: u64) -> CellReleaseFetchOptionsV2 {
    CellReleaseFetchOptionsV2 {
        limits: CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(5),
                max_cell_bytes: 1_048_576,
                parallelism: 1,
                max_connections: 1,
                max_response_bytes: response_bytes,
            },
            release: CellReleaseLimitsV1 {
                max_payload_bytes: 1_048_576,
                max_chunks: 16,
                deadline: Instant::now() + Duration::from_secs(5),
            },
        },
        transport: CellFetchTransportV2::PersistentV2 {
            max_requests: requests,
            max_requests_per_connection: requests,
        },
    }
}

struct Server {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<CellPersistentServeReportV2>>>,
}

impl Server {
    fn start(path: &Path, requests: u64, response_bytes: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let path = path.to_owned();
        let worker = thread::spawn(move || {
            serve_cells_persistent(
                &listener,
                &path,
                &stop,
                CellPersistentServeLimitsV2 {
                    serving: CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        overall_timeout: Duration::from_secs(5),
                        max_workers: 1,
                        max_connections: 1,
                        max_response_bytes: response_bytes,
                    },
                    max_requests: requests,
                    max_requests_per_connection: requests,
                },
            )
        });
        Self {
            address,
            shutdown,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> CellPersistentServeReportV2 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn all_marker_profiles_fetch_two_members_through_one_persistent_connection() {
    let fixture = Fixture::new();
    for (index, marker) in MARKERS.into_iter().enumerate() {
        let cache = fixture.cache(&format!("receiver-{index}.sqlite"));
        let output = fixture.path(&format!("complete-{index}.marker"));
        let bytes = fixture.response_bytes();
        let server = Server::start(&fixture.origin_path, 4, bytes);
        let result = fixture
            .fetch(
                marker,
                &cache,
                &[server.address],
                options(4, bytes),
                &output,
            )
            .unwrap();
        assert_eq!(result.request_attempts, 4, "{marker:?}");
        assert_eq!(result.report.connection_attempts, 1);
        assert_eq!(result.report.received_response_bytes, bytes);
        assert_eq!(result.report.cells, 2);
        assert_eq!(result.report.chunks, 2);
        assert_eq!(result.report.cached_chunks, 0);
        assert_eq!(result.report.downloaded_chunks, 2);
        assert_eq!(fs::read(&output).unwrap(), fixture.wire(marker));
        let served = server.finish();
        assert_eq!(served.request_attempts, 4);
        assert_eq!(served.serving.accepted_connections, 1);
        assert_eq!(served.serving.completed_requests, 4);
        assert_eq!(served.serving.sent_response_bytes, bytes);
    }
}

#[test]
fn aggregate_frame_exhaustion_never_publishes_and_explicit_retry_uses_verified_prefix() {
    let fixture = Fixture::new();
    for (index, marker) in MARKERS.into_iter().enumerate() {
        let cache = fixture.cache(&format!("limited-{index}.sqlite"));
        let output = fixture.path(&format!("resumed-{index}.marker"));
        let server = Server::start(&fixture.origin_path, 3, fixture.response_bytes());
        assert!(fixture
            .fetch(
                marker,
                &cache,
                &[server.address],
                options(3, fixture.response_bytes()),
                &output
            )
            .is_err());
        assert!(!output.exists(), "{marker:?}");
        let served = server.finish();
        assert_eq!(served.request_attempts, 3);
        assert_eq!(served.serving.accepted_connections, 1);
        assert_eq!(served.serving.completed_requests, 3);
        for member in &fixture.members {
            assert!(cache.manifest(member.id()).unwrap().is_some());
        }
        assert!(cache
            .chunk(fixture.members[0].chunks()[0].sha256)
            .unwrap()
            .is_some());
        assert!(cache
            .chunk(fixture.members[1].chunks()[0].sha256)
            .unwrap()
            .is_none());
        // A separate owner invocation gets a fresh finite reservation. The
        // failed invocation never reconnects or renews its exhausted budget.
        let remaining_bytes = fixture.members[1].size() + 9;
        let server = Server::start(&fixture.origin_path, 1, remaining_bytes);
        let resumed = fixture
            .fetch(
                marker,
                &cache,
                &[server.address],
                options(1, remaining_bytes),
                &output,
            )
            .unwrap();
        assert_eq!(resumed.request_attempts, 1);
        assert_eq!(resumed.report.connection_attempts, 1);
        assert_eq!(resumed.report.cached_chunks, 1);
        assert_eq!(resumed.report.downloaded_chunks, 1);
        assert_eq!(resumed.report.received_response_bytes, remaining_bytes);
        assert_eq!(fs::read(&output).unwrap(), fixture.wire(marker));
        let served = server.finish();
        assert_eq!(served.serving.completed_requests, 1);
        assert_eq!(served.serving.sent_response_bytes, remaining_bytes);
    }
}

#[test]
fn aggregate_response_budget_is_not_renewed_at_member_boundaries() {
    let fixture = Fixture::new();
    let cache = fixture.cache("short-bytes.sqlite");
    let output = fixture.path("short-bytes.tma");
    let bytes = fixture.response_bytes();
    let server = Server::start(&fixture.origin_path, 4, bytes);
    assert!(fixture
        .fetch(
            Marker::Tensor,
            &cache,
            &[server.address],
            options(4, bytes - 1),
            &output
        )
        .is_err());
    assert!(!output.exists());
    assert!(cache
        .chunk(fixture.members[0].chunks()[0].sha256)
        .unwrap()
        .is_some());
    assert!(cache
        .chunk(fixture.members[1].chunks()[0].sha256)
        .unwrap()
        .is_none());
    let served = server.finish();
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.request_attempts, 4);
}

#[test]
fn persistent_release_and_prefetch_preflight_reject_aggregate_limits_before_payload() {
    let fixture = Fixture::new();
    let manifest_bytes: u64 = fixture
        .members
        .iter()
        .map(|member| member.encode().len() as u64 + 9)
        .sum();
    let payload_bytes: u64 = fixture.members.iter().map(CellManifestV1::size).sum();
    for (index, marker) in MARKERS.into_iter().map(Some).chain([None]).enumerate() {
        for budget in ["release payload budget", "release chunk budget"] {
            let cache = fixture.cache(&format!("preflight-{index}-{budget}.sqlite"));
            let output = fixture.path(&format!("preflight-{index}-{budget}.marker"));
            let server = Server::start(&fixture.origin_path, 4, fixture.response_bytes());
            let mut options = options(4, fixture.response_bytes());
            if budget == "release payload budget" {
                options.limits.release.max_payload_bytes = payload_bytes - 1;
            } else {
                options.limits.release.max_chunks = 1;
            }
            let result = match marker {
                Some(marker) => fixture
                    .fetch(marker, &cache, &[server.address], options, &output)
                    .map(|_| ()),
                None => fetch_closure_checked(
                    &cache,
                    fixture.model.root().closure(),
                    &fixture.expected,
                    &[server.address],
                    options,
                    None,
                    None,
                )
                .map(|_| ()),
            };
            assert!(matches!(result, Err(CellErrorV1::Invalid(reason)) if reason == budget));
            assert!(!output.exists());
            let usage = cache.cache_usage().unwrap();
            assert_eq!(usage.manifest_rows, 2);
            assert_eq!(usage.chunk_rows, 0);
            // The provider could serve all four frames. Only the two metadata
            // responses are requested; the shared connection does not turn a
            // failed aggregate preflight into a partial payload acquisition.
            let served = server.finish();
            assert_eq!(served.serving.accepted_connections, 1);
            assert_eq!(served.serving.completed_requests, 2);
            assert_eq!(served.serving.sent_response_bytes, manifest_bytes);
        }
    }
}

#[test]
fn explicit_rarest_release_profile_keeps_inventory_and_all_members_on_one_v1_budget() {
    let fixture = Fixture::new();
    let cache = fixture.cache("rarest.sqlite");
    let output = fixture.path("rarest.tcd");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let path = fixture.origin_path.clone();
    let worker = thread::spawn(move || {
        serve_cells_bounded_with_availability(
            &listener,
            &path,
            &AtomicBool::new(false),
            CellServeLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(5),
                max_workers: 2,
                max_connections: 6,
                max_response_bytes: 1_048_576,
            },
        )
    });
    let mut options = options(1, 1_048_576);
    options.transport = CellFetchTransportV2::RarestFirstV1;
    options.limits.peer.max_connections = 6;
    let result = fixture
        .fetch(Marker::Closure, &cache, &[address], options, &output)
        .unwrap();
    assert_eq!(result.request_attempts, 6); // two manifests, two inventories, two chunks
    assert_eq!(result.report.connection_attempts, 6);
    assert_eq!(fs::read(output).unwrap(), fixture.wire(Marker::Closure));
    let served = worker.join().unwrap().unwrap();
    assert_eq!(served.accepted_connections, 6);
    assert_eq!(served.completed_requests, 6);
    assert_eq!(
        served.sent_response_bytes,
        result.report.received_response_bytes
    );
}

#[test]
fn residency_prefetch_stops_payload_requests_when_original_owner_cancels() {
    let fixture = Fixture::new();
    let cache = fixture.cache("cancelled-prefetch.sqlite");
    for manifest in &fixture.members {
        cache
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let source_path = fixture.origin_path.clone();
    let provider_cancel = Arc::clone(&cancelled);
    let provider_stop = Arc::clone(&stop);
    let provider = thread::spawn(move || {
        let source = CellStoreV1::open_read_only(&source_path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut queries = Vec::new();
        while !provider_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("provider accept: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut query = [0; 37];
            if stream.read_exact(&mut query).is_err() {
                continue;
            }
            assert_eq!(&query[..4], b"TCQ1");
            assert_eq!(query[4], 2, "metadata was already pinned in the cache");
            let digest = query[5..].try_into().unwrap();
            let bytes = source.chunk(digest).unwrap().unwrap();
            queries.push(digest);
            // Cancellation is external to the downloader, after a real
            // admitted payload request and before its response. Correct bytes
            // from that request cannot authorize another release member.
            provider_cancel.store(true, Ordering::Release);
            let mut header = [0; 9];
            header[..4].copy_from_slice(b"TCS1");
            header[5..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            let _ = stream
                .write_all(&header)
                .and_then(|()| stream.write_all(&bytes));
        }
        queries
    });
    let mut manager = crate::cell::CellResidencyV1::new(crate::cell::CellResidencyConfigV1 {
        max_resident_bytes: 1_048_576,
        max_resident_closures: 4,
        max_chunk_references: 16,
    })
    .unwrap();
    let mut limits = options(4, fixture.response_bytes()).limits;
    limits.peer.max_connections = 4;
    let result = manager.prefetch(
        &cache,
        fixture.model.root().closure(),
        &fixture.expected,
        &[address],
        limits,
        &cancelled,
    );
    stop.store(true, Ordering::Release);
    let queries = provider.join().unwrap();
    assert!(result.is_err());
    assert_eq!(manager.usage().resident_closures, 0);
    assert_eq!(manager.selection(), None);
    assert_eq!(
        queries.len(),
        1,
        "cancelled prefetch acquired another member"
    );
}
