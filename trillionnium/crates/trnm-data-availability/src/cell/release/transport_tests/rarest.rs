use super::*;
use crate::cell::serve_cells_persistent_rarest_first_with_ready;
use std::sync::mpsc;

fn v3_options(requests: u64, bytes: u64) -> CellReleaseFetchOptionsV2 {
    let mut options = options(requests, bytes);
    options.transport = CellFetchTransportV2::PersistentRarestFirstV3 {
        max_requests: requests,
        max_requests_per_connection: requests,
    };
    options
}

fn v3_server(path: &Path, requests: u64, bytes: u64) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = shutdown.clone();
    let path = path.to_owned();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        serve_cells_persistent_rarest_first_with_ready(
            &listener,
            &path,
            &stop,
            CellPersistentServeLimitsV2 {
                serving: CellServeLimitsV1 {
                    request_timeout: Duration::from_secs(2),
                    overall_timeout: Duration::from_secs(5),
                    max_workers: 1,
                    max_connections: 1,
                    max_response_bytes: bytes,
                },
                max_requests: requests,
                max_requests_per_connection: requests,
            },
            &|| {
                ready_tx
                    .send(())
                    .map_err(|_| CellErrorV1::Invalid("test ready receiver"))
            },
        )
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    Server {
        address,
        shutdown,
        worker: Some(worker),
    }
}

#[test]
fn v3_release_closure_model_and_tensor_keep_one_pool_and_aggregate_inventory_budget() {
    let fixture = Fixture::new();
    for (index, marker) in MARKERS.into_iter().enumerate() {
        let cache = fixture.cache(&format!("v3-receiver-{index}.sqlite"));
        let output = fixture.path(&format!("v3-complete-{index}.marker"));
        let bytes = fixture.response_bytes() + 2 * 10;
        let server = v3_server(&fixture.origin_path, 6, bytes);
        let result = fixture
            .fetch(
                marker,
                &cache,
                &[server.address],
                v3_options(6, bytes),
                &output,
            )
            .unwrap();
        assert_eq!(result.request_attempts, 6, "{marker:?}");
        assert_eq!(result.report.connection_attempts, 1);
        assert_eq!(result.report.received_response_bytes, bytes);
        assert_eq!(result.report.downloaded_chunks, 2);
        assert_eq!(result.report.cached_chunks, 0);
        assert_eq!(fs::read(output).unwrap(), fixture.wire(marker));
        let served = server.finish();
        assert_eq!(served.request_attempts, 6);
        assert_eq!(served.serving.completed_requests, 6);
        assert_eq!(served.serving.accepted_connections, 1);
        assert_eq!(served.serving.sent_response_bytes, bytes);
    }
}

#[test]
fn v3_release_inventory_cannot_renew_frames_at_member_boundary_and_resume_is_explicit() {
    let fixture = Fixture::new();
    let cache = fixture.cache("v3-frame-limited.sqlite");
    let output = fixture.path("v3-resumed.tma");
    let bytes = fixture.response_bytes() + 2 * 10;
    let server = v3_server(&fixture.origin_path, 5, bytes);
    assert!(fixture
        .fetch(
            Marker::Tensor,
            &cache,
            &[server.address],
            v3_options(5, bytes),
            &output,
        )
        .is_err());
    assert!(!output.exists());
    let served = server.finish();
    assert_eq!(served.request_attempts, 5);
    assert_eq!(served.serving.completed_requests, 5);
    assert_eq!(served.serving.accepted_connections, 1);
    assert!(cache
        .chunk(fixture.members[0].chunks()[0].sha256)
        .unwrap()
        .is_some());
    assert!(cache
        .chunk(fixture.members[1].chunks()[0].sha256)
        .unwrap()
        .is_none());
    let remaining_bytes = fixture.members[1].size() + 9 + 10;
    let server = v3_server(&fixture.origin_path, 2, remaining_bytes);
    let resumed = fixture
        .fetch(
            Marker::Tensor,
            &cache,
            &[server.address],
            v3_options(2, remaining_bytes),
            &output,
        )
        .unwrap();
    assert_eq!(resumed.request_attempts, 2);
    assert_eq!(resumed.report.connection_attempts, 1);
    assert_eq!(resumed.report.cached_chunks, 1);
    assert_eq!(resumed.report.downloaded_chunks, 1);
    assert_eq!(resumed.report.received_response_bytes, remaining_bytes);
    assert_eq!(fs::read(output).unwrap(), fixture.wire(Marker::Tensor));
    assert_eq!(server.finish().serving.completed_requests, 2);
}

#[test]
fn v3_release_inventory_cannot_renew_response_bytes_at_member_boundary() {
    let fixture = Fixture::new();
    let cache = fixture.cache("v3-byte-limited.sqlite");
    let output = fixture.path("v3-no-completion.tma");
    let bytes = fixture.response_bytes() + 2 * 10;
    let server = v3_server(&fixture.origin_path, 6, bytes);
    assert!(fixture
        .fetch(
            Marker::Tensor,
            &cache,
            &[server.address],
            v3_options(6, bytes - 1),
            &output,
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
    assert_eq!(served.request_attempts, 6);
    assert_eq!(served.serving.accepted_connections, 1);
}
