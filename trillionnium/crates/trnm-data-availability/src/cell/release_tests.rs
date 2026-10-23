//! Finite loopback checks for caller-pinned release closure transport.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::*;

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "release-loopback-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn peer_limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(15),
        max_cell_bytes: 1_048_576,
        parallelism: 1,
        max_connections: 1000,
        max_response_bytes: 4 * 1_048_576,
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: peer_limits(),
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 1_048_576,
            max_chunks: 64,
            deadline: Instant::now() + Duration::from_secs(15),
        },
    }
}

struct Peer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}

impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path)?;
            serve_cells(&listener, &store, &stop, peer_limits())
        });
        Self {
            address,
            shutdown,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    origin_path: PathBuf,
    origin: CellStoreV1,
    members: [CellManifestV1; 2],
    release: CellReleaseManifestV1,
}

impl Fixture {
    fn new() -> Self {
        Self::with_second_context(context())
    }

    fn with_second_context(second_context: CellContextV1) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let origin_path = directory.path().join("origin.sqlite");
        let origin = CellStoreV1::open(&origin_path).unwrap();
        let first_input = directory.path().join("first.input");
        let second_input = directory.path().join("second.input");
        fs::write(&first_input, vec![11; 20_000]).unwrap();
        fs::write(&second_input, vec![22; 20_000]).unwrap();
        let first = origin.pack_file(&first_input, context(), 16_384).unwrap();
        let second = origin
            .pack_file(&second_input, second_context, 16_384)
            .unwrap();
        let mut members = [first, second];
        members.sort_by_key(|manifest| manifest.id());
        let release =
            CellReleaseManifestV1::new(context(), members.iter().map(CellManifestV1::id).collect())
                .unwrap();
        Self {
            directory,
            origin_path,
            origin,
            members,
            release,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn cache(&self, name: &str) -> CellStoreV1 {
        CellStoreV1::open(&self.path(name)).unwrap()
    }

    fn successful_response_bytes(&self) -> u64 {
        self.members
            .iter()
            .map(|manifest| {
                manifest.encode().len() as u64
                    + manifest.size()
                    + 9 * (manifest.chunks().len() as u64 + 1)
            })
            .sum()
    }
}

fn copy_member(source: &CellStoreV1, target: &CellStoreV1, manifest: &CellManifestV1) {
    target
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    for chunk in manifest.chunks() {
        target
            .put_chunk(chunk, &source.chunk(chunk.sha256).unwrap().unwrap())
            .unwrap();
    }
}

fn cached_chunks(store: &CellStoreV1, members: &[CellManifestV1]) -> usize {
    members
        .iter()
        .flat_map(CellManifestV1::chunks)
        .filter(|chunk| store.chunk(chunk.sha256).unwrap().is_some())
        .count()
}

type PublicationHook = Box<dyn FnOnce(Instant)>;
thread_local! {
    static PUBLICATION_HOOK: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
    static POST_LINK_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn after_marker_link() -> CellResultV1<()> {
    if POST_LINK_ERROR.replace(false) {
        return Err(std::io::Error::other("injected post-link acknowledgement failure").into());
    }
    Ok(())
}

fn with_post_link_error<T>(run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            POST_LINK_ERROR.set(false);
        }
    }
    assert!(!POST_LINK_ERROR.replace(true));
    let _reset = Reset;
    run()
}

pub(super) fn before_marker_publication(deadline: Instant) {
    let hook = PUBLICATION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(deadline);
    }
}

fn with_publication_hook<T>(hook: PublicationHook, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = PUBLICATION_HOOK.with(|slot| slot.borrow_mut().take());
        }
    }
    PUBLICATION_HOOK.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
    let _reset = Reset;
    run()
}

fn assert_no_partial_files(directory: &Path) {
    for entry in fs::read_dir(directory).unwrap() {
        assert!(!entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial"));
    }
}

#[test]
fn release_fetch_collects_all_members_from_two_distinct_loopback_stores() {
    let fixture = Fixture::new();
    let a_path = fixture.path("a.sqlite");
    let b_path = fixture.path("b.sqlite");
    let a_store = CellStoreV1::open(&a_path).unwrap();
    let b_store = CellStoreV1::open(&b_path).unwrap();
    copy_member(&fixture.origin, &a_store, &fixture.members[0]);
    copy_member(&fixture.origin, &b_store, &fixture.members[1]);
    let a = Peer::start(&a_path);
    let b = Peer::start(&b_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("complete.tcr");
    let report = fetch_release_to_file(
        &receiver,
        &fixture.release,
        fixture.release.id(),
        &[a.address, b.address],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(report.release_id, fixture.release.id());
    assert_eq!(report.cells, 2);
    assert_eq!(report.payload_bytes, 40_000);
    assert_eq!(report.chunks, 4);
    assert_eq!(report.cached_chunks, 0);
    assert_eq!(report.downloaded_chunks, 4);
    assert_eq!(report.downloaded_bytes, 40_000);
    assert_eq!(report.supplying_peers, [a.address, b.address].into());
    assert!(report.rejected_responses > 0);
    assert_eq!(
        report.connection_attempts,
        6 + report.rejected_responses as u64
    );
    assert_eq!(
        report.received_response_bytes,
        fixture.successful_response_bytes() + 9 * report.rejected_responses as u64
    );
    receiver
        .verify_release_complete(&fixture.release, limits().release)
        .unwrap();
    assert_eq!(fs::read(&output).unwrap(), fixture.release.encode());
    assert_eq!(
        read_pinned_release(&output, fixture.release.id()).unwrap(),
        fixture.release
    );
    assert_eq!(report.connection_attempts, a.finish() + b.finish());
}

#[test]
fn post_link_failure_preserves_complete_marker_for_same_identity_readback() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("receiver.sqlite");
    for manifest in &fixture.members {
        copy_member(&fixture.origin, &receiver, manifest);
    }
    let output = fixture.path("complete.tcr");
    let mut bounded = limits();
    bounded.peer.max_response_bytes = 0;
    // The actual no-replace hard link succeeds. This cfg(test) failure models
    // the next acknowledgement boundary; it does not qualify a real disk fault.
    let result = with_post_link_error(|| {
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[],
            bounded,
            &output,
        )
    });
    assert!(matches!(result, Err(CellErrorV1::Io(error))
        if error.to_string() == "injected post-link acknowledgement failure"));
    assert_eq!(fs::read(&output).unwrap(), fixture.release.encode());
    assert_eq!(
        read_pinned_release(&output, fixture.release.id()).unwrap(),
        fixture.release
    );
    receiver
        .verify_release_complete(&fixture.release, limits().release)
        .unwrap();
    assert_no_partial_files(fixture.directory.path());
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[],
            limits(),
            &output,
        ),
        Err(CellErrorV1::Invalid("release marker exists"))
    ));
    assert_eq!(fs::read(output).unwrap(), fixture.release.encode());
}

#[test]
fn release_fetch_shares_connection_budget_and_resumes_verified_partial_cache() {
    let fixture = Fixture::new();
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("complete.tcr");
    let mut bounded = limits();
    bounded.peer.max_connections = 5;
    assert!(fetch_release_to_file(
        &receiver,
        &fixture.release,
        fixture.release.id(),
        &[peer.address],
        bounded,
        &output,
    )
    .is_err());
    assert_eq!(peer.finish(), 5);
    assert!(!output.exists());
    for member in &fixture.members {
        assert_eq!(
            receiver.manifest(member.id()).unwrap(),
            Some(member.clone())
        );
    }
    assert_eq!(cached_chunks(&receiver, &fixture.members), 3);

    let retry_peer = Peer::start(&fixture.origin_path);
    let report = fetch_release_to_file(
        &receiver,
        &fixture.release,
        fixture.release.id(),
        &[retry_peer.address],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(report.cached_chunks, 3);
    assert_eq!(report.downloaded_chunks, 1);
    assert_eq!(report.connection_attempts, 1);
    assert_eq!(retry_peer.finish(), 1);
    assert_eq!(fs::read(output).unwrap(), fixture.release.encode());
}

#[test]
fn release_fetch_parallel_response_budget_is_exact_and_one_byte_short_is_typed() {
    let fixture = Fixture::new();
    let exact = fixture.successful_response_bytes();
    let peer = Peer::start(&fixture.origin_path);
    for deficit in [0, 1] {
        let receiver = fixture.cache(&format!("receiver-{deficit}.sqlite"));
        let output = fixture.path(&format!("complete-{deficit}.tcr"));
        let mut bounded = limits();
        bounded.peer.parallelism = 4;
        bounded.peer.max_response_bytes = exact - deficit;
        let result = fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[peer.address],
            bounded,
            &output,
        );
        if deficit == 0 {
            let report = result.unwrap();
            assert_eq!(report.received_response_bytes, exact);
            assert_eq!(report.connection_attempts, 6);
            assert_eq!(report.downloaded_bytes, 40_000);
            assert_eq!(report.rejected_responses, 0);
            assert_eq!(fs::read(&output).unwrap(), fixture.release.encode());
        } else {
            assert!(matches!(
                result,
                Err(CellErrorV1::ResponseByteBudgetExhausted {
                    received_response_bytes,
                    max_response_bytes,
                }) if received_response_bytes == exact - 1 && max_response_bytes == exact - 1
            ));
            assert!(!output.exists());
            assert!(cached_chunks(&receiver, &fixture.members) < 4);
        }
    }
    assert_eq!(peer.finish(), 12);
}

fn aggregate_budget_rejected_before_chunks(payload_bytes: u64, chunks: u64, reason: &'static str) {
    let fixture = Fixture::new();
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("must-not-exist.tcr");
    let mut bounded = limits();
    bounded.release.max_payload_bytes = payload_bytes;
    bounded.release.max_chunks = chunks;
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[peer.address],
            bounded,
            &output,
        ),
        Err(CellErrorV1::Invalid(actual)) if actual == reason
    ));
    assert_eq!(peer.finish(), 2);
    assert_eq!(cached_chunks(&receiver, &fixture.members), 0);
    assert!(!output.exists());
}

#[test]
fn release_fetch_reserves_two_member_payload_total_before_any_chunk_download() {
    aggregate_budget_rejected_before_chunks(39_999, 4, "release payload budget");
}

#[test]
fn release_fetch_reserves_two_member_chunk_total_before_any_chunk_download() {
    aggregate_budget_rejected_before_chunks(40_000, 3, "release chunk budget");
}

#[test]
fn release_fetch_rejects_incompatible_member_context_before_chunks() {
    let mut incompatible = context();
    incompatible.runtime = [99; 32];
    let fixture = Fixture::with_second_context(incompatible);
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("must-not-exist.tcr");
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[peer.address],
            limits(),
            &output,
        ),
        Err(CellErrorV1::Invalid("release cell context"))
    ));
    assert!((1..=2).contains(&peer.finish()));
    assert_eq!(cached_chunks(&receiver, &fixture.members), 0);
    assert!(!output.exists());
}

#[test]
fn release_fetch_missing_member_does_not_publish_a_subset_marker() {
    let fixture = Fixture::new();
    let partial_path = fixture.path("partial.sqlite");
    let partial = CellStoreV1::open(&partial_path).unwrap();
    copy_member(&fixture.origin, &partial, &fixture.members[0]);
    let peer = Peer::start(&partial_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("must-not-exist.tcr");
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[peer.address],
            limits(),
            &output,
        ),
        Err(CellErrorV1::Unavailable)
    ));
    assert_eq!(peer.finish(), 2);
    assert_eq!(cached_chunks(&receiver, &fixture.members), 0);
    assert!(!output.exists());
}

#[test]
fn release_fetch_never_overwrites_an_existing_marker_path() {
    let fixture = Fixture::new();
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("existing.tcr");
    let original = b"caller-owned existing marker bytes";
    fs::write(&output, original).unwrap();
    assert!(fetch_release_to_file(
        &receiver,
        &fixture.release,
        fixture.release.id(),
        &[peer.address],
        limits(),
        &output,
    )
    .is_err());
    assert_eq!(fs::read(output).unwrap(), original);
    peer.finish();
}

#[test]
fn release_fetch_expired_owner_deadline_opens_no_connections() {
    let fixture = Fixture::new();
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("must-not-exist.tcr");
    let mut expired = limits();
    expired.release.deadline = Instant::now() - Duration::from_millis(1);
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            fixture.release.id(),
            &[peer.address],
            expired,
            &output,
        ),
        Err(CellErrorV1::Invalid("release fetch deadline"))
    ));
    assert_eq!(peer.finish(), 0);
    assert_eq!(cached_chunks(&receiver, &fixture.members), 0);
    assert!(!output.exists());
}

#[test]
fn release_fetch_wrong_root_pin_opens_no_connections_and_publishes_nothing() {
    let fixture = Fixture::new();
    let peer = Peer::start(&fixture.origin_path);
    let receiver = fixture.cache("receiver.sqlite");
    let output = fixture.path("must-not-exist.tcr");
    let mut wrong = fixture.release.id();
    wrong[0] ^= 1;
    assert!(matches!(
        fetch_release_to_file(
            &receiver,
            &fixture.release,
            wrong,
            &[peer.address],
            limits(),
            &output,
        ),
        Err(CellErrorV1::Invalid("release manifest digest"))
    ));
    assert_eq!(peer.finish(), 0);
    assert_eq!(cached_chunks(&receiver, &fixture.members), 0);
    assert!(!output.exists());
}

#[test]
fn pinned_release_reader_checks_root_pin_and_one_mib_file_bound() {
    let fixture = Fixture::new();
    let path = fixture.path("release.tcr");
    fs::write(&path, fixture.release.encode()).unwrap();
    assert_eq!(
        read_pinned_release(&path, fixture.release.id()).unwrap(),
        fixture.release
    );
    let mut wrong = fixture.release.id();
    wrong[0] ^= 1;
    assert!(matches!(
        read_pinned_release(&path, wrong),
        Err(CellErrorV1::Invalid("release manifest digest"))
    ));
    let mut oversized = fixture.release.encode();
    oversized.resize(1_048_577, 0);
    fs::write(&path, oversized).unwrap();
    assert!(matches!(
        read_pinned_release(&path, fixture.release.id()),
        Err(CellErrorV1::Invalid("release input size/type"))
    ));
}

#[test]
fn release_marker_sync_keeps_original_deadline_and_cleans_up_after_cutoff() {
    use std::{cell::Cell, rc::Rc, sync::mpsc};

    let fixture = Fixture::new();
    let output = fixture.path("complete.tcr");
    let root = fixture.directory.path().to_owned();
    let marker = output.clone();
    let expected = fixture.release.encode();
    let reached = Rc::new(Cell::new(false));
    let observed = reached.clone();
    let original = Instant::now() + Duration::from_secs(1);
    let mut bounded = limits();
    bounded.peer.max_response_bytes = 0;
    bounded.release.deadline = original;
    let result = with_publication_hook(
        Box::new(move |deadline| {
            assert_eq!(deadline, original, "marker publication refreshed deadline");
            observed.set(true);
            assert!(!marker.exists());
            let temporary: Vec<_> = fs::read_dir(root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    let name = path.file_name().unwrap().to_string_lossy();
                    name.starts_with(".trnm-release-") && name.ends_with(".partial")
                })
                .collect();
            assert_eq!(temporary.len(), 1);
            assert_eq!(fs::read(&temporary[0]).unwrap(), expected);
            // Hold this post-sync checkpoint past the unchanged real deadline.
            let (_hold, elapsed) = mpsc::channel::<()>();
            while let Some(left) = original.checked_duration_since(Instant::now()) {
                assert!(matches!(
                    elapsed.recv_timeout(left),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
            }
            assert!(Instant::now() > original);
        }),
        || {
            fetch_release_to_file(
                &fixture.origin,
                &fixture.release,
                fixture.release.id(),
                &[],
                bounded,
                &output,
            )
        },
    );
    assert!(reached.get(), "post-sync marker checkpoint was not reached");
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("release fetch deadline"))
    ));
    assert!(!output.exists());
    assert_no_partial_files(fixture.directory.path());
    fixture
        .origin
        .verify_release_complete(&fixture.release, limits().release)
        .unwrap();

    let report = fetch_release_to_file(
        &fixture.origin,
        &fixture.release,
        fixture.release.id(),
        &[],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(report.cached_chunks, 4);
    assert_eq!(report.downloaded_chunks, 0);
    assert_eq!(report.received_response_bytes, 0);
    assert_eq!(report.connection_attempts, 0);
    assert_eq!(fs::read(output).unwrap(), fixture.release.encode());
    assert_no_partial_files(fixture.directory.path());
}
