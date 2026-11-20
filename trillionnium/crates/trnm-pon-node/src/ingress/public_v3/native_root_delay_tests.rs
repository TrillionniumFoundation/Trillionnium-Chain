//! Actual native provenance, original settlement failure controls and TCP replay.
//! These component controls do not claim the fixed Host F0 service target.
use super::*;

fn identity(n: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
}
fn fixture() -> (
    tempfile::TempDir,
    Settings,
    Node,
    crate::Packet,
    crate::Packet,
    crate::Error,
) {
    let directory = tempfile::tempdir().unwrap();
    let now = super::super::now().unwrap();
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut node =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 2).unwrap();
    let valid = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            now - 90,
            4096,
        )
        .unwrap();
    let mut invalid = valid.clone();
    invalid.header.state[0] ^= 1;
    let (a, b) = crate::maintenance();
    let prover = trnm_crypto_primitives::pon_work::PreparedTask::new(&a, &b).unwrap();
    let mut found = false;
    for nonce in 0..4096 {
        invalid.header.nonce = nonce;
        invalid.proof = prover.prove(invalid.header.challenge()).unwrap();
        if WorkCheckedPacket::verify(invalid.clone()).is_ok() {
            found = true;
            break;
        }
    }
    assert!(found);
    let error = node
        .admit_work_checked(WorkCheckedPacket::verify(invalid.clone()).unwrap(), now)
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "ROOT");
    (directory, settings, node, valid, invalid, error)
}
fn body(packet: &crate::Packet) -> String {
    let bytes = serde_json::to_vec(&Request::Submit {
        packet: hex::encode(packet.encode().unwrap()),
    })
    .unwrap();
    hex::encode(hash(b"public-request-body-v3", &[&bytes]))
}
fn server() -> PublicServer {
    PublicServer::new(
        identity(71),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}
fn pending(digest: Hash) -> PendingNativeRootBodyDelay {
    PendingNativeRootBodyDelay {
        digest,
        deadline: Instant::now() + Duration::from_secs(10),
        stop: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

#[test]
fn actual_native_provenance_requires_complete_known_original_cpu_settlement() {
    // Native provenance is produced by a real checked execution above. This
    // isolated settlement test makes no claim to charge that earlier execution
    // to the separately acquired original CPU permit below.
    let (_directory, settings, _node, _valid, invalid, error) = fixture();
    let text = body(&invalid);
    let digest = error.completed_native_root_body(&settings, &text).unwrap();
    for failure in 0..6 {
        let server = server();
        let metrics = Mutex::new(PublicMetrics::default());
        let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
        let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
        match failure {
            0 => {}
            1 => measurement.unavailable.set(true),
            2 => server.fail_next_cpu_finish.store(true, Ordering::Release),
            3 => server
                .fail_next_live_cpu_finish
                .store(true, Ordering::Release),
            4 => measurement.workers.unknown(),
            5 => {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = server.mutation_cpu.lock().unwrap();
                    panic!("intentional original budget lock poison");
                }));
            }
            _ => unreachable!(),
        }
        let (_, output) = permit.finish_observed_with_root_delay(
            &measurement,
            &server,
            &metrics,
            None,
            Some(pending(digest)),
        );
        // Known settlement permits only an owned, unpublished transfer. A
        // worker completing or dropping it never impersonates a wire response.
        assert_eq!(output.is_some(), failure == 0, "failure={failure}");
        assert_eq!(server.body_refusals.retry_at(&text, Instant::now()), None);
        drop(output);
        assert_eq!(server.body_refusals.retry_at(&text, Instant::now()), None);
        if failure != 0 {
            assert!(metrics.lock().unwrap().mutation_cpu_clock_failures > 0);
        }
    }
}

#[test]
fn final_cancel_stop_and_expiry_cannot_publish_completed_native_body_delay() {
    let (_directory, settings, _node, _valid, invalid, error) = fixture();
    let text = body(&invalid);
    let digest = error.completed_native_root_body(&settings, &text).unwrap();
    for refusal in 0..3 {
        let server = server();
        let metrics = Mutex::new(PublicMetrics::default());
        let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
        let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
        let mut hint = pending(digest);
        match refusal {
            0 => hint.cancelled.store(true, Ordering::Release),
            1 => hint.stop.store(true, Ordering::Release),
            2 => hint.deadline = Instant::now(),
            _ => unreachable!(),
        }
        let (_, output) = permit.finish_observed_with_root_delay(
            &measurement,
            &server,
            &metrics,
            None,
            Some(hint),
        );
        assert!(output.is_none());
        assert_eq!(metrics.lock().unwrap().mutation_cpu_clock_failures, 0);
        assert_eq!(server.body_refusals.retry_at(&text, Instant::now()), None);
    }
}

#[test]
fn unpublished_completion_output_orphan_and_late_cancellation_drop_native_delay() {
    // Actual native provenance; the independent settlement samples below do
    // not claim to charge the earlier fixture execution. TCP is tested below.
    let (_directory, settings, _node, _valid, invalid, error) = fixture();
    let text = body(&invalid);
    let digest = error.completed_native_root_body(&settings, &text).unwrap();
    for route in 0..6 {
        let server = server();
        let metrics = Mutex::new(PublicMetrics::default());
        let permit = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
        let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
        let (_, output) = permit.finish_observed_with_root_delay(
            &measurement,
            &server,
            &metrics,
            None,
            Some(pending(digest)),
        );
        let mut output = output.unwrap();
        assert_eq!(server.body_refusals.retry_at(&text, Instant::now()), None);
        if route <= 2 {
            let pool = Arc::new(Mutex::new(0_usize));
            let permit = BufferPermit::acquire(pool.clone(), 32, MAX_OUTPUT_BYTES).unwrap();
            if route == 1 {
                // Dropping a partially advanced original Output owner is not
                // a complete write. This unit check does not assert kernel I/O.
                drop(Stage::Output {
                    bytes: vec![7; 32],
                    cursor: 1,
                    _permit: Some(permit),
                    root_delay: Some(output),
                });
            } else {
                let done = Finished {
                    id: 1,
                    bytes: Ok(vec![7; 32]),
                    permit: Some(permit),
                    root_delay: Some(output),
                    _observation: None,
                };
                if route == 0 {
                    let (sender, receiver) = mpsc::sync_channel(1);
                    sender.send(done).ok().unwrap();
                    drop(receiver);
                } else {
                    apply_finished_connection(
                        &mut BTreeMap::new(),
                        done,
                        &metrics,
                        Instant::now(),
                        Instant::now() + Duration::from_secs(1),
                        &AtomicBool::new(false),
                    )
                    .unwrap();
                }
            }
            assert_eq!(*pool.lock().unwrap(), 0);
        } else {
            match route {
                3 => output.0.cancelled.store(true, Ordering::Release),
                4 => output.0.stop.store(true, Ordering::Release),
                5 => output.0.deadline = Instant::now(),
                _ => unreachable!(),
            }
            output.publish(&server);
        }
        assert_eq!(
            server.body_refusals.retry_at(&text, Instant::now()),
            None,
            "route={route}"
        );
        assert_eq!(metrics.lock().unwrap().mutation_cpu_clock_failures, 0);
    }
}

#[test]
fn real_tcp_root_retry_reexecutes_and_failed_output_never_creates_delay() {
    for fault in 0..3 {
        let fail_output = fault == 1;
        let fail_write = fault == 2;
        let (_directory, settings, node, valid, invalid, error) = fixture();
        let owner = super::tests::shared(node);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = server();
        server
            .fail_next_output
            .store(fail_output, Ordering::Release);
        server
            .fail_next_output_write
            .store(fail_write, Ordering::Release);
        let policy = server.policy;
        let observed = Arc::new(Mutex::new(PublicMetrics::default()));
        let serving_owner = Arc::clone(&owner);
        let serving_stop = Arc::clone(&stop);
        let serving_metrics = Arc::clone(&observed);
        let observer = PublicRequestObserver::new_with_authenticated_callers(3).unwrap();
        let serving_observer = observer.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                serving_owner,
                Duration::from_secs(10),
                serving_stop,
                server,
                serving_metrics,
                serving_observer,
            )
            .unwrap()
        });
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let call = |packet: &crate::Packet| {
                call_public_protected_v3(
                    address,
                    &Request::Submit {
                        packet: hex::encode(packet.encode().unwrap()),
                    },
                    &settings,
                    identity(71).public_key(),
                    &identity(80),
                    policy,
                )
            };
            let first = call(&invalid);
            if fail_output || fail_write {
                assert!(first.is_err());
            } else {
                let first = first.unwrap();
                assert!(!first.ok);
                assert_eq!(first.value["error"], "ROOT");
            }
            let wait_before = observed.lock().unwrap().pending_grant_wait_ns;
            let repeated = call(&invalid).unwrap();
            assert!(!repeated.ok);
            assert_eq!(repeated.value["error"], "ROOT");
            let waited = observed.lock().unwrap().pending_grant_wait_ns - wait_before;
            eprintln!("actual native body delay: fault={fault} grant_wait_ns={waited}");
            // This is the actual local grant stage with no competing client,
            // not a fixed-Host performance qualification.
            if fail_output || fail_write {
                assert!(
                    waited < 200_000_000,
                    "failed output fault={fault} wait={waited}"
                );
            } else {
                assert!(
                    waited >= 300_000_000,
                    "original bounded delay wait={waited}"
                );
            }
            assert_eq!(
                owner.lock().unwrap().read_active().unwrap().0,
                settings.genesis()
            );
            assert!(call(&valid).unwrap().ok);
        }));
        stop.store(true, Ordering::Release);
        let metrics = worker.join().unwrap();
        outcome.unwrap();
        assert_eq!(metrics.work_started, 3);
        assert_eq!(metrics.work_finished, 3);
        assert_eq!(metrics.work_failed, 0);
        assert_eq!(metrics.completed_submit, 1);
        assert_eq!(metrics.executor_refusals, 2);
        assert_eq!(metrics.mutation_cpu_reservations, 3);
        assert_eq!(metrics.mutation_cpu_clock_failures, 0);
        assert!(metrics.mutation_cpu_charged_ns > 0);
        assert_eq!(
            metrics.mutation_full_work_cpu_ns + metrics.mutation_dispatch_excluding_work_cpu_ns,
            metrics.mutation_cpu_charged_ns
        );
        assert_eq!(metrics.paid_body_reserved_bytes_after_shutdown, 0);
        let snapshot = observer.snapshot();
        assert!(snapshot.coverage_complete());
        assert_eq!(snapshot.records.len(), 3);
        for row in &snapshot.records[..2] {
            // This expected digest is the actual authenticated Hello/Cookie
            // received on TCP, not a reimplementation of the new streaming hash.
            let wire_body = row.body_digest.unwrap();
            assert_eq!(
                error.completed_native_root_body(&settings, &hex::encode(wire_body)),
                Some(wire_body),
            );
            assert_eq!(row.full_work_accepted, Some(true));
            assert_eq!(row.dispatch_accepted, Some(false));
        }
        assert_eq!(
            snapshot.records[0].response_frame_complete,
            !fail_output && !fail_write,
        );
        assert!(snapshot.records[1].response_frame_complete);
        assert_eq!(snapshot.records[2].dispatch_accepted, Some(true));
        assert_eq!(
            error.completed_native_root_body(
                &settings,
                &hex::encode(snapshot.records[2].body_digest.unwrap()),
            ),
            None,
        );
        eprintln!(
            "actual TCP provenance: {}",
            json!({
                "fault": fault,
                "body_digests": snapshot.records.iter().map(|row| &row.body_digest).collect::<Vec<_>>(),
                "complete_response_frames": snapshot.records.iter().map(|row| row.response_frame_complete).collect::<Vec<_>>(),
                "full_work_executions": metrics.work_finished,
                "paid_cpu_ns": metrics.mutation_cpu_charged_ns,
            })
        );
    }
}
