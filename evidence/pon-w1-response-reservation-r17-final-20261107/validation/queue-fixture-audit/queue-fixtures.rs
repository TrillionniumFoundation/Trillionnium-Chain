        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner = shared(Node::open(directory.path(), settings, 1).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let observer = PublicRequestObserver::new(1).unwrap();
        let records = observer.clone();
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                Arc::new(Mutex::new(PublicMetrics::default())),
                records,
            )
            .unwrap()
        });
        let raw = serde_json::to_vec(&Request::Head).unwrap();
        let mut h = hello(2, raw.len());
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let (mut socket, sizes) = paid_grant_counted(address, h, &identity(72), policy).unwrap();
        client_write(&mut socket, &raw, Instant::now() + Duration::from_secs(2)).unwrap();
        let response_raw =
            client_frame(&mut socket, 16384, Instant::now() + Duration::from_secs(2)).unwrap();
        let response: Response = serde_json::from_slice(&response_raw).unwrap();
        assert!(response.ok);
        verify_hex_strict(
            identity(71).public_key(),
            &response.message().unwrap(),
            &response.signature,
        )
        .unwrap();
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert!(row.complete && row.frames.iter().all(|frame| frame.complete));
        assert_eq!(row.frames[1].bytes_written, sizes[0] as u64);
        assert_eq!(row.frames[3].bytes_written, sizes[1] as u64);
        assert_eq!(row.frames[5].bytes_written, (4 + response_raw.len()) as u64);
        assert_eq!(
            row.application_bytes_read,
            Some((HELLO_BYTES + SOLUTION_BYTES + raw.len()) as u64)
        );
        assert_eq!(
            row.application_bytes_written,
            Some((sizes[0] + sizes[1] + 4 + response_raw.len()) as u64)
        );
    }
    #[test]
    fn request_observer_records_actual_partial_read_eof_and_quantum_writes() {
        use std::net::Shutdown;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let observer = PublicRequestObserver::new(1).unwrap();
        let record = observer.connection().unwrap();
        client.write_all(&[1, 2, 3, 4, 5]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        assert!(
            !read_available_observed(&mut socket, &mut bytes, HELLO_BYTES, Some(&record), 0)
                .unwrap()
        );
        assert!(
            read_available_observed(&mut socket, &mut bytes, HELLO_BYTES, Some(&record), 0)
                .is_err()
        );
        assert_eq!(bytes, [1, 2, 3, 4, 5]);
        let output = vec![9; IO_QUANTUM + 17];
        let mut cursor = 0;
        assert!(
            !write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        assert_eq!(cursor, IO_QUANTUM);
        let mut received = vec![0; IO_QUANTUM];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, output[..IO_QUANTUM]);
        assert!(
            write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        let mut tail = [0; 17];
        client.read_exact(&mut tail).unwrap();
        assert_eq!(tail, [9; 17]);
        record.terminal("hello");
        drop(record);
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert_eq!(row.frames[0].bytes_read, 5);
        assert!(!row.frames[0].complete);
        assert_eq!(row.frames[5].bytes_written, output.len() as u64);
        assert!(row.frames[5].complete && row.response_frame_complete && row.complete);
        assert_eq!(row.application_bytes_read, Some(5));
        assert_eq!(row.application_bytes_written, Some(output.len() as u64));
        assert_eq!(row.dispatch_thread_cpu_ns, None);
        assert_eq!(row.full_work_thread_cpu_ns, None);
    }
    #[test]
    fn request_observer_retains_partial_output_bytes_after_actual_write_error() {
        use std::net::Shutdown;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let observer = PublicRequestObserver::new(1).unwrap();
        let record = observer.connection().unwrap();
        let output = vec![7; IO_QUANTUM + 17];
        let mut cursor = 0;
        assert!(
            !write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).unwrap()
        );
        let mut received = vec![0; IO_QUANTUM];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, output[..IO_QUANTUM]);
        socket.shutdown(Shutdown::Write).unwrap();
        assert!(
            write_available_observed(&mut socket, &output, &mut cursor, Some(&record), 5).is_err()
        );
        assert_eq!(cursor, IO_QUANTUM);
        record.terminal("output");
        drop(record);
        let snapshot = observer.snapshot();
        let row = &snapshot.records[0];
        assert!(row.complete && !row.response_frame_complete);
        assert_eq!(row.frames[5].bytes_written, IO_QUANTUM as u64);
        assert_eq!(row.application_bytes_written, Some(IO_QUANTUM as u64));
        assert!(!row.frames[5].complete);
        assert_eq!(row.physical_network_bytes, None);
    }
    #[test]
    fn paid_mutation_body_budget_preserves_signed_read_service_with_rotating_callers() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner = shared(Node::open(directory.path(), settings.clone(), 2).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let signal = stop.clone();
        let counters = metrics.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                owner,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let sizes = [
            MAX_BODY,
            (MAX_PAID_BODY_BYTES - READ_BODY_RESERVE) / 3 - MAX_BODY,
        ];
        let mut held = Vec::new();
        for (index, size) in sizes.into_iter().enumerate() {
            let caller = identity(80 + index as u8);
            let mut h = hello(1, size);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        assert_eq!(
            metrics.lock().unwrap().peak_paid_body_bytes,
            MAX_PAID_BODY_BYTES - READ_BODY_RESERVE
        );
        let caller = identity(83);
        let mut h = hello(1, 1);
        h.caller = digest(caller.public_key()).unwrap();
        assert!(paid_grant(address, h, &caller, policy).is_err());
        let reply = call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(84),
            policy,
        )
        .unwrap();
        assert!(reply.ok);
        assert_eq!(reply.value["height"], 0);
        drop(held);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.paid_body_capacity_refusals, 0);
        assert_eq!(m.pending_grant_closed, 1);
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
        assert_eq!(m.completed_read, 1);
        assert_eq!(m.work_started, 0);
        assert!(m.peak_paid_body_bytes <= MAX_PAID_BODY_BYTES);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn paid_mutation_grants_are_global_across_identity_rotation_and_release_on_eof() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let signal = stop.clone();
        let counters = metrics.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                shared(source),
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let mut held = Vec::new();
        for index in 0..MAX_MUTATING_GRANTS {
            let caller = identity(80 + index as u8);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        let caller = identity(90);
        let mut h = hello(1, 1);
        h.caller = digest(caller.public_key()).unwrap();
        assert!(paid_grant(address, h, &caller, policy).is_err());
        let reply = call_public_protected_v3(
            address,
            &Request::Head,
            &settings,
            identity(71).public_key(),
            &identity(91),
            policy,
        )
        .unwrap();
        assert!(reply.ok);
        drop(held);
        wait_metric(&metrics, |m| {
            m.retained_phase_errors.get("body").copied().unwrap_or(0) >= MAX_MUTATING_GRANTS as u64
        });
        let reply = call_public_protected_v3(
            address,
            &Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
            &settings,
            identity(71).public_key(),
            &identity(92),
            policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.lane_capacity_refusals, 0);
        assert_eq!(m.pending_grant_closed, 1);
        assert_eq!(
            m.pending_grant_entered,
            m.pending_grant_granted + m.pending_grant_closed
        );
        assert_eq!(m.peak_mutating_grants, MAX_MUTATING_GRANTS);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.work_finished, 1);
        assert_eq!(m.work_failed, 0);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let raw = serde_json::to_vec(&request).unwrap();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let observer = PublicRequestObserver::new(8).unwrap();
        let records = observer.clone();
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
                records,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v3(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy
            )
            .unwrap()
            .ok
        );
        let locked = owner.lock().unwrap();
        let before = locked.active().unwrap();
        let caller = identity(80);
        let mut h = hello(1, raw.len());
        h.caller = digest(caller.public_key()).unwrap();
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let mut sockets = Vec::new();
        for _ in 0..3 {
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        // Initial Head was one task. Two Submit workers are waiting for this
        // actual owner lock, leaving the third preserved request in the queue.
        wait_metric(&metrics, |m| {
            m.tasks_enqueued == 4 && m.tasks_dequeued == 3 && m.mutation_cpu_reservations == 2
        });
        sockets[0].shutdown(std::net::Shutdown::Write).unwrap();
        for socket in &sockets[1..] {
            socket.shutdown(std::net::Shutdown::Both).unwrap();
        }
        wait_metric(&metrics, |m| m.disconnected_await_requests == 3);
        // Keep the first caller's read half open: it receives EOF because the
        // server explicitly cancels R2 write-half-closed requests.
        assert!(client_frame(
            &mut sockets[0],
            MAX_RESPONSE,
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
        drop(sockets);
        drop(locked);
        wait_metric(&metrics, |m| m.abandoned_tasks == 3);
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        assert_eq!(owner.lock().unwrap().active().unwrap(), before);
        let reply = call_public_protected_v3(
            address,
            &request,
            &settings,
            identity(71).public_key(),
            &identity(81),
            policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.disconnected_await_requests, 3);
        assert_eq!(m.abandoned_tasks, 3);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        let snapshot = observer.snapshot();
        assert!(snapshot.coverage_complete());
        assert_eq!(m.mutation_cpu_reservations, 3);
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter(|row| row.cpu_settlement.is_some())
                .count(),
            3,
            "both actually dispatched cancellations and the later success settle once"
        );
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter_map(|row| row.cpu_settlement)
                .map(|actual| actual.total_cpu_ns.unwrap())
                .sum::<u64>(),
            m.mutation_cpu_charged_ns,
            "per-request samples retain cancelled work and equal the original paid CPU total"
        );
        let abandoned: Vec<_> = snapshot
            .records
            .iter()
            .filter(|row| row.dispatch_error_code == Some("PUBLIC_REQUEST_CANCELLED"))
            .collect();
        assert_eq!(abandoned.len(), 2);
        for row in abandoned {
            assert_eq!(row.dispatch_accepted, Some(false));
            assert!(!row.response_frame_complete);
            assert!(!row.full_work_started);
            let phase = row
                .submit_phases
                .iter()
                .find(|phase| phase.phase == SubmitPhase::CpuSettle)
                .unwrap();
            assert!(phase.started && phase.completed);
            assert_eq!(phase.accepted, Some(true));
            assert!(phase.wall_ns.is_some());
            assert!(row.cpu_settlement.unwrap().budget_settled);
            let actual = row.cpu_settlement.unwrap();
            assert_eq!(actual.owner_cpu_ns, row.dispatch_thread_cpu_ns);
            assert_eq!(
                actual.total_cpu_ns,
                actual
                    .owner_cpu_ns
                    .zip(actual.scoped_worker_cpu_ns)
                    .and_then(|(owner, workers)| owner.checked_add(workers))
            );
        }
        let skipped: Vec<_> = snapshot
            .records
            .iter()
            .filter(|row| row.operation == Some(1) && !row.dispatch_started)
            .collect();
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].cpu_settlement.is_none());
        assert!(
            !skipped[0]
                .submit_phases
                .iter()
                .find(|phase| phase.phase == SubmitPhase::CpuSettle)
                .unwrap()
                .started
        );
    }
    #[test]
    fn disconnecting_paid_requests_waiting_for_queue_cancels_without_starting_work() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let request = Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        };
        let raw = serde_json::to_vec(&request).unwrap();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v3(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy
            )
            .unwrap()
            .ok
        );
        let locked = owner.lock().unwrap();
        let before = locked.active().unwrap();
        let caller = identity(80);
        let mut h = hello(1, raw.len());
        h.caller = digest(caller.public_key()).unwrap();
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let mut sockets = Vec::new();
        for _ in 0..8 {
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        // Initial Head was one task. Two Submit workers are waiting for this
        // actual owner lock, leaving two in the channel and four inside bounded pending connections.
        wait_metric(&metrics, |m| {
            m.tasks_enqueued == 5 && m.tasks_dequeued == 3 && m.peak_pending_enqueue == 4
        });
        sockets[0].shutdown(std::net::Shutdown::Write).unwrap();
        for socket in &sockets[1..] {
            socket.shutdown(std::net::Shutdown::Both).unwrap();
        }
        wait_metric(&metrics, |m| m.disconnected_await_requests == 8);
        // Keep the first caller's read half open: it receives EOF because the
        // server explicitly cancels R2 write-half-closed requests.
        assert!(client_frame(
            &mut sockets[0],
            MAX_RESPONSE,
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
        drop(sockets);
        drop(locked);
        wait_metric(&metrics, |m| m.abandoned_tasks == 4);
        assert_eq!(metrics.lock().unwrap().work_started, 0);
        assert_eq!(owner.lock().unwrap().active().unwrap(), before);
        let reply = call_public_protected_v3(
            address,
            &request,
            &settings,
            identity(71).public_key(),
            &identity(81),
            policy,
        )
        .unwrap();
        assert!(reply.ok, "{}", reply.value);
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.disconnected_await_requests, 8);
        assert_eq!(m.disconnected_before_enqueue, 4);
        assert_eq!(m.abandoned_tasks, 4);
        assert_eq!(m.work_started, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn completed_input_boundary_rejects_tail_without_consuming_pending_frame() {
        for half_close in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut caller = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (socket, _) = listener.accept().unwrap();
            socket.set_nonblocking(true).unwrap();
            let cancelled = AtomicBool::new(false);
            let metrics = Mutex::new(PublicMetrics::default());
            caller_write_half_alive(&socket, &cancelled, &metrics).unwrap();
            assert!(!cancelled.load(Ordering::Acquire));
            caller.write_all(b"X").unwrap();
            if half_close {
                caller.shutdown(std::net::Shutdown::Write).unwrap();
            }
            // Establish actual socket arrival, without consuming the byte or
            // interpreting a buffered pending frame as a completed body tail.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(socket.peek(&mut [0; 1]).unwrap(), 1);
            socket.set_nonblocking(true).unwrap();
            assert!(caller_write_half_open(&socket, false).unwrap());
            let error = caller_write_half_alive(&socket, &cancelled, &metrics).unwrap_err();
            assert!(error.is(crate::ErrorCode::PublicTrailingInput));
            assert_eq!(error.kind(), crate::ErrorKind::Transport);
            assert!(cancelled.load(Ordering::Acquire));
            assert_eq!(metrics.lock().unwrap().disconnected_await_requests, 0);
            let mut byte = [0; 1];
            assert_eq!(socket.peek(&mut byte).unwrap(), 1);
            assert_eq!(byte, *b"X");
        }
    }
    #[test]
    fn early_complete_body_waiting_for_ready_preserves_signed_native_submission() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let packet = source
            .make(
                source.active().unwrap().0,
                vec![],
                crate::development_public(0).unwrap(),
                clock - 50,
                4096,
            )
            .unwrap();
        let raw = serde_json::to_vec(&Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        })
        .unwrap();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(8),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        let mut held = Vec::new();
        for index in 0..8 {
            let caller = identity(80 + index);
            let mut h = hello(1, 1);
            h.caller = digest(caller.public_key()).unwrap();
            held.push(paid_grant(address, h, &caller, policy).unwrap());
        }
        let caller = identity(90);
        let mut h = hello(1, raw.len());
        h.caller = digest(caller.public_key()).unwrap();
        h.digest = hash(b"public-request-body-v3", &[&raw]);
        let (mut socket, cookie, _, deadline) =
            paid_solution_only(address, h, &caller, policy).unwrap();
        client_write(&mut socket, &raw, deadline).unwrap();
        wait_metric(&metrics, |m| m.pending_grant_entered == 9);
        // An actual independent read forces further reactor progress while all
        // mutation grants are still held and the early body is in the socket.
        assert!(
            call_public_protected_v3(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(91),
                policy,
            )
            .unwrap()
            .ok
        );
        {
            let m = metrics.lock().unwrap();
            assert_eq!(m.pending_grant_entered, 10);
            assert_eq!(m.pending_grant_granted, 9);
            assert_eq!(m.pending_grant_closed, 0);
            assert_eq!(m.work_started, 0);
            assert_eq!(m.mutation_cpu_reservations, 0);
            assert_eq!(
                m.body_bytes_received,
                serde_json::to_vec(&Request::Head).unwrap().len() as u64
            );
        }
        drop(held.pop());
        let ready: Value =
            serde_json::from_slice(&client_frame(&mut socket, 256, deadline).unwrap()).unwrap();
        assert_eq!(ready["cookie_digest"], hex::encode(cookie.id().unwrap()));
        // Do not send a second body: the pending bytes must now be read by the
        // ordinary bounded body stage and complete genuine native verification.
        let response: Response = serde_json::from_slice(
            &client_frame(
                &mut socket,
                response_maximum(1),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap(),
        )
        .unwrap();
        verify_hex_strict(
            identity(71).public_key(),
            &response.message().unwrap(),
            &response.signature,
        )
        .unwrap();
        assert!(response.ok, "{}", response.value);
        assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
        drop((socket, held));
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.work_started, 1);
        assert_eq!(m.completed_submit, 1);
        assert_eq!(m.mutation_cpu_reservations, 1);
        assert_eq!(m.mutation_cpu_in_flight_after_shutdown, 0);
        assert_eq!(m.mutation_cpu_clock_failures, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
    }
    #[test]
    fn trailing_input_after_complete_body_cancels_without_starting_work() {
        for half_close in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let clock = super::super::now().unwrap();
            let settings = Settings::development(Some(clock - 100)).unwrap();
            let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
            let packet = source
                .make(
                    source.active().unwrap().0,
                    vec![],
                    crate::development_public(0).unwrap(),
                    clock - 50,
                    4096,
                )
                .unwrap();
            let request = Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            };
            let raw = serde_json::to_vec(&request).unwrap();
            let owner = shared(source);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
            let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
            let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
            let server = PublicServer::new(identity(71), policy).unwrap();
            let cpu_domain = server.mutation_cpu_domain();
            let worker = thread::spawn(move || {
                serve_public_protected_v3_with_metrics(
                    listener,
                    node,
                    Duration::from_secs(8),
                    signal,
                    server,
                    counters,
                )
                .unwrap()
            });
            assert!(
                call_public_protected_v3(
                    address,
                    &Request::Head,
                    &settings,
                    identity(71).public_key(),
                    &identity(72),
                    policy
                )
                .unwrap()
                .ok
            );
            let locked = owner.lock().unwrap();
            let before = locked.active().unwrap();
            let caller = identity(80);
            let mut h = hello(1, raw.len());
            h.caller = digest(caller.public_key()).unwrap();
            h.digest = hash(b"public-request-body-v3", &[&raw]);
            let mut sockets = Vec::new();
            for _ in 0..8 {
                let mut socket = paid_grant(address, h, &caller, policy).unwrap();
                socket.write_all(&raw).unwrap();
                sockets.push(socket);
            }
            // Initial Head was one task. Two Submit workers are waiting for this
            // actual owner lock, leaving two in the channel and four inside bounded pending connections.
            wait_metric(&metrics, |m| {
                m.tasks_enqueued == 5 && m.tasks_dequeued == 3 && m.peak_pending_enqueue == 4
            });
            // The entire declared body was already received and queued. Extra bytes
            // are not another request; they must not hide a subsequent TCP FIN.
            for socket in &mut sockets {
                socket.write_all(b"X").unwrap();
                if half_close {
                    socket.shutdown(std::net::Shutdown::Write).unwrap();
                }
            }
            wait_metric(&metrics, |m| {
                m.retained_phase_errors.get("queue").copied().unwrap_or(0)
                    + m.retained_phase_errors.get("work").copied().unwrap_or(0)
                    == 8
            });
            // Both open and half-closed callers lose the malformed transport. The
            // original task obligation remains until its existing worker settles.
            assert!(client_frame(
                &mut sockets[0],
                MAX_RESPONSE,
                Instant::now() + Duration::from_secs(2)
            )
            .is_err());
            drop(sockets);
            drop(locked);
            wait_metric(&metrics, |m| m.abandoned_tasks == 4);
            assert_eq!(metrics.lock().unwrap().work_started, 0);
            assert_eq!(owner.lock().unwrap().active().unwrap(), before);
            let reply = call_public_protected_v3(
                address,
                &request,
                &settings,
                identity(71).public_key(),
                &identity(81),
                policy,
            )
            .unwrap();
            assert!(reply.ok, "{}", reply.value);
            assert_eq!(owner.lock().unwrap().stats().unwrap()["height"], 1);
            stop.store(true, Ordering::Release);
            let m = worker.join().unwrap();
            assert_eq!(m.disconnected_await_requests, 0);
            assert_eq!(m.disconnected_before_enqueue, 0);
            assert_eq!(m.abandoned_tasks, 4);
            assert_eq!(m.work_started, 1);
            assert_eq!(m.completed_submit, 1);
            assert_eq!(m.mutating_grants_after_shutdown, 0);
            assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
            // Dequeue precedes its alive/reserve check. Cancellation may race
            // any of the four actually queued mutations; only the final valid
            // retry must reserve. The exact account identity below governs all
            // real reservations and settlements, not a scheduler coincidence.
            assert!((1..=5).contains(&m.mutation_cpu_reservations));
            assert_eq!(m.mutation_cpu_in_flight_after_shutdown, 0);
            assert_eq!(m.mutation_cpu_clock_failures, 0);
            assert!(!m.mutation_cpu_unavailable_after_shutdown);
            assert!(m.mutation_cpu_charged_ns > 0);
            assert!(m.mutation_cpu_credit_ns_after_shutdown <= MUTATION_CPU_BURST_NS);
            let flow = cpu_domain.observe_actual_flow().unwrap().unwrap();
            assert!(flow.balance_identity_verified);
            assert_eq!(flow.live_owners, 0);
            assert_eq!(flow.booked_reservation_ns, 0);
            assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
            assert_eq!(flow.settled_full_cpu_ns, m.mutation_cpu_charged_ns);
        }
    }
    #[test]
    fn eight_paid_submits_wait_for_full_queue_without_losing_body_or_absolute_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let clock = super::super::now().unwrap();
        let settings = Settings::development(Some(clock - 100)).unwrap();
        let source = Node::open(directory.path(), settings.clone(), 2).unwrap();
        let parent = source.active().unwrap().0;
        let packets: Vec<_> = (0..MAX_MUTATING_GRANTS)
            .map(|index| {
                source
                    .make(
                        parent,
                        vec![],
                        crate::development_public(index as u64).unwrap(),
                        clock - 50,
                        4096,
                    )
                    .unwrap()
            })
            .collect();
        let owner = shared(source);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (signal, counters, node) = (stop.clone(), metrics.clone(), owner.clone());
        let worker = thread::spawn(move || {
            serve_public_protected_v3_with_metrics(
                listener,
                node,
                Duration::from_secs(12),
                signal,
                PublicServer::new(identity(71), policy).unwrap(),
                counters,
            )
            .unwrap()
        });
        assert!(
            call_public_protected_v3(
                address,
                &Request::Head,
                &settings,
                identity(71).public_key(),
                &identity(72),
                policy
            )
            .unwrap()
            .ok
        );
        let locked = owner.lock().unwrap();
        let mut sockets = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            let raw = serde_json::to_vec(&Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            })
            .unwrap();
            let caller = identity(80 + index as u8);
            let mut h = hello(1, raw.len());
            h.caller = digest(caller.public_key()).unwrap();
            h.digest = hash(b"public-request-body-v3", &[&raw]);
            let mut socket = paid_grant(address, h, &caller, policy).unwrap();
            socket.write_all(&raw).unwrap();
            sockets.push(socket);
        }
        wait_metric(&metrics, |m| {
            m.tasks_enqueued == 5
                && m.tasks_dequeued == 3
                && m.peak_pending_enqueue == 4
                && m.queue_backpressure_events >= 4
        });
        // The two workers and two channel slots are occupied. Four complete paid
        // requests retain their permits inside bounded connections, not a new queue.
        assert_eq!(metrics.lock().unwrap().queue_refusals, 0);
        drop(locked);
        for (socket, packet) in sockets.iter_mut().zip(&packets) {
            let bytes = client_frame(
                socket,
                MAX_RESPONSE,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            let response: Response = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response.profile, hex::encode(policy.id()));
            verify_hex_strict(
                identity(71).public_key(),
                &response.message().unwrap(),
                &response.signature,
            )
            .unwrap();
            assert!(response.ok, "{}", response.value);
            assert_eq!(response.value["block"], hex::encode(packet.id().unwrap()));
        }
        drop(sockets);
        stop.store(true, Ordering::Release);
        let m = worker.join().unwrap();
        assert_eq!(m.work_started, 8);
        assert_eq!(m.work_finished, 8);
        assert_eq!(m.work_failed, 0);
        assert_eq!(m.completed_submit, 8);
        assert_eq!(m.queue_refusals, 0);
        assert_eq!(m.enqueued_after_backpressure, 4);
        assert!(m.queue_wait_ns > 0);
        assert_eq!(m.peak_mutating_grants, MAX_MUTATING_GRANTS);
        assert_eq!(m.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(m.mutating_grants_after_shutdown, 0);
        assert_eq!(m.read_grants_after_shutdown, 0);
    }
    #[test]
    fn queue_backpressure_preserves_deadline_and_releases_permits_on_drop() {
        let settings = Settings::development(Some(1)).unwrap();
        let server = server();
        let cookie = server
            .cookie(&settings, hello(2, 1), "127.0.0.1:1".parse().unwrap())
            .unwrap();
        let body_pool = Arc::new(Mutex::new(0));
        let lane_pool = Arc::new(Mutex::new(0));
        let metrics = Mutex::new(PublicMetrics::default());
        let (sender, receiver) = mpsc::sync_channel(2);
        let ready_at = Instant::now();
        let deadline = ready_at + Duration::from_millis(WORK_MS);
        let make_task = |id| Task {
            observation: None,
            _permit: BufferPermit::acquire(body_pool.clone(), 3, MAX_PAID_BODY_BYTES).unwrap(),
            _lane_permit: Arc::new(
                BufferPermit::acquire(lane_pool.clone(), 1, MAX_READ_GRANTS).unwrap(),
            ),
            id,
            cookie: cookie.clone(),
            raw_body: serde_json::to_vec(&Request::Head).unwrap(),
            ready_at,
            backpressure_seen: false,
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        assert!(matches!(
            enqueue_paid_task(make_task(1), &sender, &metrics).unwrap(),
            Stage::Await
        ));
        assert!(matches!(
            enqueue_paid_task(make_task(2), &sender, &metrics).unwrap(),
            Stage::Await
        ));
        let mut task = make_task(3);
        for _ in 0..4 {
            let Stage::Enqueue(pending) = enqueue_paid_task(task, &sender, &metrics).unwrap()
            else {
                panic!("full channel must retain paid task");
            };
            assert_eq!(pending.deadline, deadline);
            assert_eq!(pending.ready_at, ready_at);
            assert!(pending.backpressure_seen);
            assert_eq!(*body_pool.lock().unwrap(), 9);
            assert_eq!(*lane_pool.lock().unwrap(), 3);
            task = *pending;
        }
        drop(task);
        assert_eq!(*body_pool.lock().unwrap(), 6);
        assert_eq!(*lane_pool.lock().unwrap(), 2);
        drop(receiver.try_recv().unwrap());
        drop(receiver.try_recv().unwrap());
        assert_eq!(*body_pool.lock().unwrap(), 0);
        assert_eq!(*lane_pool.lock().unwrap(), 0);
        assert_eq!(metrics.lock().unwrap().queue_backpressure_events, 4);
        assert_eq!(metrics.lock().unwrap().queue_refusals, 0);
    }

    fn wait_for_released_pool(pool: &Mutex<usize>) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            if *pool.lock().unwrap() == 0 {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            thread::yield_now();
        }
    }

    #[test]
    fn dropped_queue_task_is_not_observed_closed_before_its_last_grant_releases() {
        let settings = Settings::development(Some(1)).unwrap();
        let raw_body = serde_json::to_vec(&Request::Head).unwrap();
        let cookie = server()
            .cookie(
                &settings,
                hello(2, raw_body.len()),
                "127.0.0.1:1".parse().unwrap(),
            )
            .unwrap();
        let body_pool = Arc::new(Mutex::new(0));
        let lane_pool = Arc::new(Mutex::new(0));
        let observer = PublicRequestObserver::new(1).unwrap();
        let connection = observer.connection().unwrap();
        connection.identity(1);
        connection.request(2, [3; 32]);
        let record = connection.task();
        let ready_at = Instant::now();
        record.queue_started(ready_at);
        let task = Task {
            id: 1,
            cookie,
            _permit: BufferPermit::acquire(
                body_pool.clone(),
                raw_body.len() * 3,
                MAX_PAID_BODY_BYTES,
            )
            .unwrap(),
            _lane_permit: Arc::new(
                BufferPermit::acquire(lane_pool.clone(), 1, MAX_READ_GRANTS).unwrap(),
            ),
            raw_body,
            ready_at,
            backpressure_seen: false,
            deadline: ready_at + Duration::from_millis(WORK_MS),
            cancelled: Arc::new(AtomicBool::new(true)),
            observation: Some(record),
        };
        connection.terminal_error("shutdown", &"PUBLIC_REQUEST_CANCELLED".into());
        drop(connection);
        let (sender, receiver) = mpsc::sync_channel(2);
        sender.send(task).ok().unwrap();
