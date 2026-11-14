use super::*;
use crate::cell::{
    release_snapshot::tests::{expected as owner_expected, fixture, owners},
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellFileRoleV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellReleaseSnapshotV1, CellTensorContractV1,
    CellTensorModelManifestV1,
};
use std::{net::TcpListener, thread};

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 64 << 20,
        max_logical_bytes: 32 << 20,
        max_chunk_rows: 128,
        max_manifest_rows: 64,
    }
}

fn plan(
    store: &CellStoreV1,
    snapshot: &CellReleaseSnapshotV1,
    deadline: Instant,
) -> CellBep52ReleasePlanV2 {
    let bindings = snapshot
        .version()
        .manifests()
        .iter()
        .map(|manifest| {
            CellBep52StorageBindingV2::from_pinned_store(
                manifest,
                manifest.id(),
                manifest.context(),
                store,
                CellReleaseLimitsV1 {
                    max_payload_bytes: manifest.size(),
                    max_chunks: manifest.chunks().len() as u64,
                    deadline,
                },
            )
            .unwrap()
        })
        .collect();
    let (model, environment) = owners(snapshot);
    let expected = owner_expected(snapshot, &model, &environment);
    CellBep52ReleasePlanV2::new(snapshot.version().clone(), &expected.version, bindings).unwrap()
}

fn limits(
    plan: &CellBep52ReleasePlanV2,
    deadline: Instant,
    connections: u64,
    readbacks: u64,
) -> CellBep52ReleaseLimitsV2 {
    CellBep52ReleaseLimitsV2 {
        deadline,
        request_timeout: Duration::from_secs(5),
        max_connections: connections,
        max_received_bytes: 1 << 20,
        max_sent_bytes: 1 << 20,
        max_messages: 4000,
        max_readback_bytes: readbacks * plan.payload_bytes(),
        max_readback_chunks: readbacks * plan.chunks(),
        max_readback_attempts: readbacks,
    }
}

/// Extend the shared typed fixture with five reachable Configuration members.
/// The original model, tokenizer, rules, tensor schema and environment remain
/// real members of the new independently committed complete release.
fn nine_member_fixture() -> (tempfile::TempDir, CellStoreV1, CellReleaseSnapshotV1) {
    let (directory, store, snapshot) = fixture();
    let original = snapshot.version().model().closure();
    let mut files = original.files().to_vec();
    let mut manifests = snapshot.version().manifests().to_vec();
    for i in 0..5 {
        let bytes = format!("aux-setting-{i}").into_bytes();
        let chunk = CellChunkV1 {
            size: bytes.len() as u32,
            sha256: Sha256::digest(&bytes).into(),
        };
        let manifest = CellManifestV1::new(
            original.release().context().clone(),
            bytes.len() as u64,
            chunk.sha256,
            16384,
            vec![chunk.clone()],
        )
        .unwrap();
        store.put_chunk(&chunk, &bytes).unwrap();
        store
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        let index = files.len() as u16;
        files[0].dependencies.push(index);
        files.push(CellClosureFileV1 {
            path: format!("z-aux-{i}.cfg"),
            role: CellFileRoleV1::Configuration,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: vec![],
        });
        manifests.push(manifest);
    }
    let closure = CellReleaseClosureV1::new(
        original.release().context().clone(),
        original.selected_generation(),
        original.loader_profile(),
        original.roots().to_vec(),
        files,
    )
    .unwrap();
    let root = CellModelReleaseRootV1::new(closure, snapshot.version().model().lineage().to_vec())
        .unwrap();
    let contract =
        CellTensorContractV1::new(root.id(), snapshot.tensors().contract().files().to_vec())
            .unwrap();
    let tensors = CellTensorModelManifestV1::new(root.clone(), contract).unwrap();
    manifests.sort_by_key(CellManifestV1::id);
    let version =
        CellVersionManifestV1::new(root, snapshot.version().environment().clone(), manifests)
            .unwrap();
    let extended = CellReleaseSnapshotV1::new(
        version,
        tensors,
        snapshot.composition_file(),
        snapshot.composition_profile(),
    )
    .unwrap();
    assert_eq!(extended.version().manifests().len(), 9);
    (directory, store, extended)
}

fn accept_until(listener: &TcpListener, deadline: Instant) -> CellResultV1<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                require(
                    Instant::now() < deadline,
                    "release test original accept deadline",
                )?;
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[test]
fn release_nine_real_tcp_members_share_one_reservation_and_refuse_tenth_connection() {
    let (directory, source, snapshot) = nine_member_fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let pin = plan.commitment();
    let reservation = limits(&plan, deadline, 9, 1);
    let listeners: Vec<_> = (0..9)
        .map(|_| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .collect();
    let addresses: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    let source_path = directory.path().join("cache.sqlite");
    let server_plan = plan.clone();
    let server_snapshot = snapshot.clone();
    let worker = thread::spawn(move || -> CellResultV1<CellBep52PeerUsageV1> {
        let store = CellStoreV1::open_read_only(&source_path)?;
        let (model, environment) = owners(&server_snapshot);
        let expected = owner_expected(&server_snapshot, &model, &environment);
        let mut session = CellBep52ReleaseSessionV2::new(
            [41; 32],
            &server_plan,
            pin,
            &expected.version,
            reservation,
        )?;
        for (index, listener) in listeners.iter().enumerate() {
            let stream = accept_until(listener, deadline)?;
            session.serve_member(
                &store,
                index,
                pin,
                &expected.version,
                stream,
                *b"-CV2001-seed-peer001",
            )?;
            assert_eq!(session.deadline(), deadline);
            assert_eq!(session.usage().connection_attempts, index as u64 + 1);
        }
        Ok(session.usage().clone())
    });
    let destination =
        CellStoreV1::open(&directory.path().join("received.sqlite"), config()).unwrap();
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let mut session =
        CellBep52ReleaseSessionV2::new([42; 32], &plan, pin, &expected.version, reservation)
            .unwrap();
    let acquired = (|| -> CellResultV1<u64> {
        let mut downloaded = 0;
        for (index, address) in addresses.iter().enumerate() {
            let report = session.fetch_member(
                &destination,
                index,
                pin,
                &expected.version,
                &[*address],
                *b"-CV2001-read-peer001",
            )?;
            assert_eq!(report.manifest_id, plan.bindings()[index].manifest_id());
            assert_eq!(report.cached_chunks, 0);
            assert_eq!(report.downloaded_chunks, 1);
            assert_eq!(session.deadline(), deadline);
            assert_eq!(session.usage().connection_attempts, index as u64 + 1);
            downloaded += report.downloaded_bytes;
        }
        Ok(downloaded)
    })();
    let server_usage = worker.join().unwrap().unwrap();
    assert_eq!(acquired.unwrap(), plan.payload_bytes());
    assert_eq!(server_usage.connection_attempts, 9);
    assert_eq!(server_usage.refused_connections, 0);
    assert_eq!(session.usage().connection_attempts, 9);
    assert_eq!(session.usage().completed_fetches, 9);
    assert!(session.usage().received_bytes > plan.payload_bytes());
    assert_eq!(session.usage().received_bytes, server_usage.sent_bytes);
    assert_eq!(session.usage().sent_bytes, server_usage.received_bytes);
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 9);
    assert_eq!(destination.cache_usage().unwrap().manifest_rows, 9);

    let readback = session
        .verify_complete(&destination, pin, &expected.version)
        .unwrap();
    assert_eq!(readback.commitment, snapshot.version().commitment());
    assert_eq!(readback.manifests, 9);
    assert_eq!(readback.payload_bytes, plan.payload_bytes());
    assert_eq!(readback.chunks, plan.chunks());
    assert_eq!(
        session.readback_usage(),
        &CellBep52ReleaseReadUsageV2 {
            reserved_bytes: plan.payload_bytes(),
            reserved_chunks: plan.chunks(),
            attempts: 1,
            completed: 1,
        }
    );

    // A fresh empty destination forces an actual cold request. Reusing the
    // original owner cannot turn the ninth successful transfer into a reset.
    let cold = CellStoreV1::open(&directory.path().join("tenth.sqlite"), config()).unwrap();
    let tenth = TcpListener::bind("127.0.0.1:0").unwrap();
    let before = session.usage().clone();
    let error = session
        .fetch_member(
            &cold,
            0,
            pin,
            &expected.version,
            &[tenth.local_addr().unwrap()],
            *b"-CV2001-read-peer001",
        )
        .unwrap_err();
    assert!(error.to_string().contains("BEP52 connection budget"));
    assert_eq!(session.usage(), &before);
    assert_eq!(cold.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(session.deadline(), deadline);
}

#[test]
fn release_failed_final_readbacks_keep_whole_charge_and_exhaust_retries() {
    let (directory, source, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let pin = plan.commitment();
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let mut session = CellBep52ReleaseSessionV2::new(
        [43; 32],
        &plan,
        pin,
        &expected.version,
        limits(&plan, deadline, 1, 2),
    )
    .unwrap();
    let partial = CellStoreV1::open(&directory.path().join("partial.sqlite"), config()).unwrap();
    let first = plan.bindings()[0].manifest();
    partial.put_manifest(first.id(), &first.encode()).unwrap();
    for chunk in first.chunks() {
        let bytes = source.chunk(chunk.sha256).unwrap().unwrap();
        partial.put_chunk(chunk, &bytes).unwrap();
    }
    for attempt in 1..=2 {
        assert!(session
            .verify_complete(&partial, pin, &expected.version)
            .is_err());
        assert_eq!(
            session.readback_usage(),
            &CellBep52ReleaseReadUsageV2 {
                reserved_bytes: attempt * plan.payload_bytes(),
                reserved_chunks: attempt * plan.chunks(),
                attempts: attempt,
                completed: 0,
            }
        );
    }
    let charged = session.readback_usage().clone();
    let error = session
        .verify_complete(&source, pin, &expected.version)
        .unwrap_err();
    assert!(error.to_string().contains("remaining full readback budget"));
    assert_eq!(session.readback_usage(), &charged);
    assert_eq!(session.usage(), &CellBep52PeerUsageV1::default());
    assert_eq!(session.deadline(), deadline);
}

#[test]
fn release_plan_version_pins_and_latched_cancellation_precede_io() {
    let (directory, source, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let pin = plan.commitment();
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let reservation = limits(&plan, deadline, 9, 1);
    let mut other_pin = pin;
    other_pin[0] ^= 1;
    let mut other_version = expected.version.commitment;
    other_version[0] ^= 1;
    let wrong_version = CellVersionLoaderContextV1 {
        commitment: other_version,
        model: &model,
        environment: &environment,
    };
    assert!(CellBep52ReleaseSessionV2::new(
        [44; 32],
        &plan,
        other_pin,
        &expected.version,
        reservation,
    )
    .is_err());
    assert!(
        CellBep52ReleaseSessionV2::new([44; 32], &plan, pin, &wrong_version, reservation,).is_err()
    );
    let mut session =
        CellBep52ReleaseSessionV2::new([44; 32], &plan, pin, &expected.version, reservation)
            .unwrap();
    let destination =
        CellStoreV1::open(&directory.path().join("guarded.sqlite"), config()).unwrap();
    for (current_pin, current_version) in [(other_pin, &expected.version), (pin, &wrong_version)] {
        assert!(session
            .fetch_member(
                &destination,
                0,
                current_pin,
                current_version,
                &[],
                *b"-CV2001-read-peer001",
            )
            .is_err());
        assert!(session
            .verify_complete(&destination, current_pin, current_version)
            .is_err());
    }
    assert!(session
        .fetch_member(
            &destination,
            usize::MAX,
            pin,
            &expected.version,
            &[],
            *b"-CV2001-read-peer001",
        )
        .is_err());
    let cancelled = session.cancellation_handle();
    cancelled.store(true, Ordering::Release);
    assert!(session
        .fetch_member(
            &destination,
            0,
            pin,
            &expected.version,
            &[],
            *b"-CV2001-read-peer001",
        )
        .is_err());
    cancelled.store(false, Ordering::Release);
    assert!(session
        .fetch_member(
            &destination,
            0,
            pin,
            &expected.version,
            &[],
            *b"-CV2001-read-peer001",
        )
        .is_err());
    assert!(session
        .verify_complete(&source, pin, &expected.version)
        .is_err());
    assert_eq!(session.usage(), &CellBep52PeerUsageV1::default());
    assert_eq!(
        session.readback_usage(),
        &CellBep52ReleaseReadUsageV2::default()
    );
    assert_eq!(destination.cache_usage().unwrap().manifest_rows, 0);
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn release_plan_rejects_missing_duplicate_and_foreign_members() {
    let (_directory, source, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let mut missing = plan.bindings().to_vec();
    missing.pop();
    assert!(
        CellBep52ReleasePlanV2::new(snapshot.version().clone(), &expected.version, missing,)
            .is_err()
    );
    let mut duplicate = plan.bindings().to_vec();
    duplicate[0] = duplicate[1].clone();
    assert!(
        CellBep52ReleasePlanV2::new(snapshot.version().clone(), &expected.version, duplicate,)
            .is_err()
    );
    let original = plan.bindings()[0].manifest();
    let mut changed_context = original.context().clone();
    changed_context.family.push_str("-other-release");
    let foreign = CellManifestV1::new(
        changed_context,
        original.size(),
        original.payload_sha256(),
        original.chunk_bytes(),
        original.chunks().to_vec(),
    )
    .unwrap();
    let foreign_binding = CellBep52StorageBindingV2::from_pinned_store(
        &foreign,
        foreign.id(),
        foreign.context(),
        &source,
        CellReleaseLimitsV1 {
            max_payload_bytes: foreign.size(),
            max_chunks: foreign.chunks().len() as u64,
            deadline,
        },
    )
    .unwrap();
    let mut mixed = plan.bindings().to_vec();
    mixed[0] = foreign_binding;
    assert!(
        CellBep52ReleasePlanV2::new(snapshot.version().clone(), &expected.version, mixed,).is_err()
    );
    let mut reversed = plan.bindings().to_vec();
    reversed.reverse();
    let canonical =
        CellBep52ReleasePlanV2::new(snapshot.version().clone(), &expected.version, reversed)
            .unwrap();
    assert_eq!(canonical.commitment(), plan.commitment());
}

#[test]
fn release_v2_admission_leaves_v1_eight_connection_cap_unchanged() {
    let (_directory, source, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let reservation = limits(&plan, deadline, 9, 1);
    let mut old = CellBep52PeerLimitsV1 {
        deadline,
        request_timeout: reservation.request_timeout,
        max_connections: 9,
        max_received_bytes: reservation.max_received_bytes,
        max_sent_bytes: reservation.max_sent_bytes,
        max_messages: reservation.max_messages,
    };
    assert!(CellBep52PeerSessionV1::new([45; 32], old).is_err());
    old.max_connections = 8;
    assert!(CellBep52PeerSessionV1::new([45; 32], old).is_ok());
    assert!(CellBep52ReleaseSessionV2::new(
        [45; 32],
        &plan,
        plan.commitment(),
        &expected.version,
        reservation,
    )
    .is_ok());
}

#[test]
fn release_accepted_connection_is_charged_when_source_preparation_fails() {
    let (directory, source, snapshot) = fixture();
    let deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, deadline);
    let pin = plan.commitment();
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let mut session = CellBep52ReleaseSessionV2::new(
        [46; 32],
        &plan,
        pin,
        &expected.version,
        limits(&plan, deadline, 1, 1),
    )
    .unwrap();
    let empty =
        CellStoreV1::open(&directory.path().join("missing-source.sqlite"), config()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, endpoint) = listener.accept().unwrap();
    assert_eq!(endpoint, client.local_addr().unwrap());
    assert!(session
        .serve_member(
            &empty,
            0,
            pin,
            &expected.version,
            stream,
            *b"-CV2001-seed-peer001",
        )
        .is_err());
    assert_eq!(session.usage().connection_attempts, 1);
    assert_eq!(session.usage().refused_connections, 1);
    assert_eq!(session.usage().received_bytes, 0);
    assert_eq!(session.usage().sent_bytes, 0);
    assert_eq!(session.refusals().len(), 1);
    assert_eq!(session.refusals()[0].0, endpoint);
    let before = session.usage().clone();
    let _second = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let error = session
        .serve_member(
            &source,
            0,
            pin,
            &expected.version,
            stream,
            *b"-CV2001-seed-peer001",
        )
        .unwrap_err();
    assert!(error.to_string().contains("BEP52 connection budget"));
    assert_eq!(session.usage(), &before);
    assert_eq!(
        session.readback_usage(),
        &CellBep52ReleaseReadUsageV2::default()
    );
}

#[test]
fn release_cached_continuations_do_not_renew_the_original_deadline() {
    let (_directory, source, snapshot) = fixture();
    let preparation_deadline = Instant::now() + Duration::from_secs(30);
    let plan = plan(&source, &snapshot, preparation_deadline);
    let pin = plan.commitment();
    let (model, environment) = owners(&snapshot);
    let expected = owner_expected(&snapshot, &model, &environment);
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut session = CellBep52ReleaseSessionV2::new(
        [47; 32],
        &plan,
        pin,
        &expected.version,
        limits(&plan, deadline, 9, 1),
    )
    .unwrap();
    session
        .fetch_member(
            &source,
            0,
            pin,
            &expected.version,
            &[],
            *b"-CV2001-read-peer001",
        )
        .unwrap();
    assert_eq!(session.usage().completed_fetches, 1);
    thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    let before = session.usage().clone();
    let error = session
        .fetch_member(
            &source,
            1,
            pin,
            &expected.version,
            &[],
            *b"-CV2001-read-peer001",
        )
        .unwrap_err();
    assert!(error.to_string().contains("BEP52 original deadline"));
    assert_eq!(session.deadline(), deadline);
    assert_eq!(session.usage(), &before);
    assert_eq!(
        session.readback_usage(),
        &CellBep52ReleaseReadUsageV2::default()
    );
}
