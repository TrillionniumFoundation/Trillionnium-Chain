            "PUBLIC_READY",
        )?;
        client_write(
            &mut stream,
            &raw,
            total_deadline.min(Instant::now() + Duration::from_millis(BODY_MS)),
        )?;
        let bytes = client_frame(
            &mut stream,
            pq_identity::response_maximum_for(op, pq),
            total_deadline.min(Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS)),
        )?;
        let r: Response = serde_json::from_slice(&bytes)?;
        ensure(
            serde_json::to_vec(&r)? == bytes
                && r.schema
                    == pq_identity::schema(
                        pq,
                        "public-protected-response-v3",
                        "public-protected-response-pq-v4",
                    )
                && r.profile == hex::encode(expected_profile)
                && r.network == hex::encode(settings.network())
                && r.parameters == hex::encode(settings.parameters())
                && r.genesis == hex::encode(settings.genesis())
                && r.server == pinned_server
                && r.cookie_digest == hex::encode(id)
                && r.request_digest == hex::encode(hello.digest),
            "PUBLIC_RESPONSE_CONTEXT",
        )?;
        server_pin
            .verify(&r.message()?, &r.signature)
            .map_err(|_| "PUBLIC_RESPONSE_SIGNATURE")?;
        if outer_deadline.is_some() {
            ensure(Instant::now() < total_deadline, "PUBLIC_CLIENT_DEADLINE")?;
        }
        metrics.solution_body_response_ns = elapsed_ns(phase_start);
        phase = PublicClientStage::Complete;
        Ok(PublicReply {
            ok: r.ok,
            value: r.value,
            solve_trials: nonce + 1,
            solve_elapsed_ns,
            body_bytes_sent: raw.len(),
            public_network_ready: false,
            identity_authority: false,
        })
    })();
    if result.is_err() {
        metrics.record_failure(phase, elapsed_ns(phase_start));
    }
    metrics.total_elapsed_ns = elapsed_ns(call_start);
    (result, metrics)
}

#[cfg(test)]
fn validate_challenge_context(
    raw: &[u8],
    cookie: &Cookie,
    hello: &Hello,
    settings: &Settings,
    pinned_server: &str,
    policy: PublicPolicy,
    expected_profile: Hash,
) -> Result<()> {
    validate_challenge_context_authenticated(
        raw,
        cookie,
        hello,
        settings,
        &ServerPin::Classical(pinned_server),
        policy,
        expected_profile,
    )
}

fn validate_challenge_context_authenticated(
    raw: &[u8],
    cookie: &Cookie,
    hello: &Hello,
    settings: &Settings,
    server_pin: &ServerPin<'_>,
    policy: PublicPolicy,
    expected_profile: Hash,
) -> Result<()> {
    ensure(
        serde_json::to_vec(cookie)? == raw
            && cookie.schema
                == pq_identity::schema(
                    server_pin.is_pq(),
                    "public-resource-cookie-v3",
                    "public-resource-cookie-pq-v4",
                )
            && cookie.profile == hex::encode(expected_profile)
            && cookie.network == hex::encode(settings.network())
            && cookie.parameters == hex::encode(settings.parameters())
            && cookie.genesis == hex::encode(settings.genesis())
            && cookie.server == server_pin.public_key()
            && cookie.caller == hex::encode(hello.caller)
            && cookie.op == hello.op
            && cookie.body_len as usize == hello.len
            && cookie.body_digest == hex::encode(hello.digest)
            && cookie.client_nonce == hex::encode(hello.client_nonce)
            && cookie.bits == policy.bits
            && cookie.lifetime_ms == policy.lifetime_ms
            && cookie.expires_tick_ms.checked_sub(cookie.issued_tick_ms)
                == Some(policy.lifetime_ms),
        "PUBLIC_CHALLENGE_CONTEXT",
    )?;
    server_pin
        .verify(&cookie.server_message()?, &cookie.signature)
        .map_err(|_| "PUBLIC_CHALLENGE_SIGNATURE".into())
}

fn client_frame(stream: &mut TcpStream, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    super::read_exact_deadline(stream, &mut prefix, deadline)?;
    let n = u32::from_be_bytes(prefix) as usize;
    ensure(n > 0 && n <= maximum, "PUBLIC_CLIENT_FRAME_LIMIT")?;
    let mut bytes = vec![0; n];
    super::read_exact_deadline(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn client_write(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("PUBLIC_CLIENT_DEADLINE")?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err("PUBLIC_EOF".into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    ensure(Instant::now() < deadline, "PUBLIC_CLIENT_DEADLINE")
}

#[cfg(all(test, target_os = "linux"))]
mod shared_cpu_domain_source_tests {
    use super::*;
    #[test]
    fn public_server_meter_clone_and_original_dispatch_use_the_same_real_bucket() {
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
        let server = PublicServer::new(
            identity,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let domain = server.mutation_cpu_domain();
        assert!(domain.shares_domain_with(&server.mutation_cpu_domain()));
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let operation = domain.begin().unwrap();
                barrier.wait();
                barrier.wait();
                operation.finish()
            });
            barrier.wait();
            assert_eq!(server.mutation_cpu.lock().unwrap().in_flight, 1);
            let metrics = Mutex::new(PublicMetrics::default());
            let original = PaidMutationCpuPermit::acquire(&server, &metrics).unwrap();
            assert_eq!(server.mutation_cpu.lock().unwrap().in_flight, 2);
            assert_eq!(
                domain.begin().err().unwrap().to_string(),
                "PUBLIC_MUTATION_CPU_BUDGET"
            );
            let measurement = MutationCpuMeasurement::for_permit(Some(&original));
            original.finish(&measurement, &server, &metrics);
            barrier.wait();
            assert!(!worker.join().unwrap().accounting_unavailable);
        });
        assert_eq!(server.mutation_cpu.lock().unwrap().in_flight, 0);
    }

    #[test]
    fn process_cold_real_w1_cpu_depletion_preserves_read_and_recovers_honest_admission() {
        // An isolated native proof-cost test, not a production test hook:
        // no synthetic negative credit, modified budget, trusted remote client,
        // artificial CPU telemetry or changed Work semantics. Every debit is
        // sampled from actual W1 replay on the existing charged request thread.
        use trnm_crypto_primitives::pon_work;
        let settings = Settings::development(Some(1_750_000_000)).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let node = Node::open(&directory.path().join("receiver"), settings.clone(), 1).unwrap();
        let valid = node
            .make(
                settings.genesis(),
                vec![],
                crate::development_public(0).unwrap(),
                settings.genesis_time() + 2,
                4096,
            )
            .unwrap();
        // Real unmodified W1 proof is required before creating the fake ticket.
        WorkCheckedPacket::verify(valid.clone()).unwrap();
        let mut false_packet = valid.clone();
        let pos = false_packet.proof.len() - 32;
        let challenge = false_packet.header.challenge();
        let original_tail = &false_packet.proof[pos..];
        let mut found = false;
        for nonce in 0u64..4096 {
            let tail = hash(
                b"public-v3-false-trace-v2",
                &[&challenge, &nonce.to_le_bytes()],
            );
            if tail.as_slice() != original_tail
                && hash(b"ticket", &[&challenge, &tail]) <= false_packet.header.target
            {
                false_packet.proof[pos..].copy_from_slice(&tail);
                found = true;
                break;
            }
        }
        assert!(
            found,
            "no valid fake-ticket challenge in original bounded search"
        );
        assert_eq!(
            WorkCheckedPacket::verify(false_packet.clone())
                .err()
                .unwrap()
                .to_string(),
            "WORK:Transcript"
        );
        let server = PublicServer::new_process_cold(
            DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let domain = server.mutation_cpu_domain();
        let initial = domain.observe().unwrap();
        assert_eq!(initial.stored_credit_ns, 0);
        let metrics = Mutex::new(PublicMetrics::default());
        let stop = AtomicBool::new(false);
        let cancelled = AtomicBool::new(false);
        let permit = PaidMutationCpuPermit::acquire_before(
            &server,
            &metrics,
            Instant::now() + Duration::from_secs(2),
            &stop,
            &cancelled,
        )
        .unwrap();
        let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
        let source_thread_cpu = ThreadCpuStamp::start().unwrap();
        let mut replayed = 0u64;
        let mut depleted = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        for _ in 0..20_000 {
            assert!(
                Instant::now() < deadline,
                "native W1 failed to exhaust real paid CPU within bounded window"
            );
            replayed += 1;
            let result = WorkCheckedPacket::verify_with_progress(false_packet.clone(), &mut |_| {
                measurement.workers.checkpoint()
            });
            match result {
                Err(error) if error.to_string() == "WORK:Transcript" => {}
                Err(error) if error.to_string() == "PUBLIC_MUTATION_CPU_BUDGET" => {
                    depleted = true;
                    break;
                }
                _ => panic!("original W1 false transcript/cancel semantics changed"),
            }
            match measurement.workers.checkpoint() {
                Err(error) if error.to_string() == "PUBLIC_MUTATION_CPU_BUDGET" => {
                    depleted = true;
                    break;
                }
                Ok(()) => {}
                Err(other) => panic!("real W1 CPU measurement unavailable: {other}"),
            }
        }
        let consumed = source_thread_cpu.finish().unwrap();
        measurement.full_work_ns.set(Some(consumed));
        assert!(depleted && replayed > 1, "CPU did not actually exhaust");
        assert!(consumed > 0, "no actual W1 work CPU measured");
        // The exhausted request must settle its real charged interval.
        assert!(permit.finish(&measurement, &server, &metrics).is_some());
        let actual = domain.observe().unwrap();
        assert_eq!(actual.in_flight, 0);
        assert!(!actual.accounting_unavailable);
        assert!(metrics.lock().unwrap().mutation_cpu_refusals > 0);

        // True read + signed native submit through the existing TCP service
        // after the exhausted budget starts refilling. The unchanged call has
        // its original 2-second deadline and cannot fabricate ledger authority.
        let mut node = node;
        // The ordinary public service requires a trusted, pre-existing native
        // mempool. This is an owner fixture, never enabled by a guest.
        node.enable_local_mempool(crate::PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 4,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: crate::development_public(0).unwrap(),
        })
        .unwrap();
        let shared = Arc::new(Mutex::new(node));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let terminate = Arc::new(AtomicBool::new(false));
        let thread_stop = terminate.clone();
        let receiver = shared.clone();
        let worker = thread::spawn(move || {
            serve_public_protected_v3(
                listener,
                receiver,
                Duration::from_secs(6),
                thread_stop,
                server,
            )
        });
        let client_policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let client = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
        let server_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
        let pinned = server_identity.public_key();
        let read = call_public_protected_v3_with_deadline(
            address,
            &Request::Head,
            &settings,
            pinned,
            &client,
            client_policy,
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(
            read.0.unwrap().ok,
            "unpaid Head must survive real CPU exhaustion"
        );
        let honest = call_public_protected_v3_with_deadline(
            address,
            &Request::Submit {
                packet: hex::encode(valid.encode().unwrap()),
            },
            &settings,
            pinned,
            &client,
            client_policy,
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(
            honest.0.unwrap().ok,
            "signed honest Submit must recover via original CPU refill"
        );
        terminate.store(true, Ordering::Release);
        let finished = worker.join().unwrap().unwrap();
        assert_eq!(finished.mutation_cpu_in_flight_after_shutdown, 0);
        assert_eq!(finished.mutation_cpu_clock_failures, 0);
        let actual_state = shared.lock().unwrap().read_active().unwrap();
        let mut independent =
            Node::open(&directory.path().join("consumer"), settings.clone(), 1).unwrap();
        let accepted_id = independent
            .admit(&valid, super::super::now().unwrap())
            .unwrap();
        independent
            .activate_observed(accepted_id, super::super::now().unwrap())
            .unwrap();
        assert_eq!(actual_state, independent.read_active().unwrap());
        println!(
            "{}",
            json!({"schema":"original-W1-paid-CPU-real-depletion-lab-v1",
                "replayed_actual_W1_invalid_proofs":replayed,
                "paid_thread_cpu_ns":consumed,
                "original_cpu_meter_start_ns":initial.stored_credit_ns,
                "meter_after_real_depletion_ns":actual.stored_credit_ns,
                "cpu_refusals":metrics.lock().unwrap().mutation_cpu_refusals,
                "honest_read_and_native_submit_recovered":true,
                "independently_verified_state":true,
                "wan_and_sybil_qualified":false,
                "production_activation":false})
        );
        // Read-only assertion of protocol bounds; constructor and policy unchanged.
        assert_eq!(pon_work::PROOF_BYTES, 49_188);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w1_negative_cache_explicit_settings_are_bounded_before_service_startup() {
        let make = || {
            PublicServer::new(
                DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
                PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            )
            .unwrap()
        };
        assert!(make().w1_rejection_cache.is_none());
        let selected = make()
            .with_w1_rejection_cache(8, Duration::from_secs(1))
            .unwrap();
        assert!(selected.w1_rejection_cache.is_some());
        assert!(make()
            .with_w1_rejection_cache(0, Duration::from_secs(1))
            .is_err());
        assert!(make()
            .with_w1_rejection_cache(8, Duration::from_secs(60))
            .is_err());
        // Signed policy identity remains the original V3 identity. This is
        // strictly optional/local and is not an activated protocol migration.
        assert_eq!(selected.policy.id(), make().policy.id());
    }

    #[test]
    fn client_stage_identity_preserves_observation_labels_and_exact_failed_phase_accounting() {
        let initial = || PublicClientMetrics {
            construction_ns: 11,
            challenge_ns: 12,
            solution_search_ns: 13,
            solution_trials: 17,
            solution_found: true,
            solution_body_response_ns: 14,
            total_elapsed_ns: 19,
            failed_stage: None,
        };
        let mut expected = json!({
            "construction_ns": 11,
            "challenge_ns": 12,
            "solution_search_ns": 13,
            "solution_trials": 17,
            "solution_found": true,
            "solution_body_response_ns": 14,
            "total_elapsed_ns": 19,
            "failed_stage": null,
        });
        assert_eq!(serde_json::to_value(initial()).unwrap(), expected);
        for (stage, label, changed_field) in [
            (
                PublicClientStage::Construction,
                "construction",
                Some("construction_ns"),
            ),
            (
                PublicClientStage::Challenge,
                "challenge",
                Some("challenge_ns"),
            ),
            (
                PublicClientStage::SolutionSearch,
                "solution-search",
                Some("solution_search_ns"),
            ),
            (
                PublicClientStage::SolutionBodyResponse,
                "solution-body-response",
                Some("solution_body_response_ns"),
            ),
            (PublicClientStage::Complete, "complete", None),
            (
                PublicClientStage::Unknown("future-stage"),
                "future-stage",
                None,
            ),
            (PublicClientStage::Unknown("challenge"), "challenge", None),
            (
                PublicClientStage::Unknown("solution-search"),
                "solution-search",
                None,
            ),
            (
                PublicClientStage::Unknown("solution-body-response"),
                "solution-body-response",
                None,
            ),
        ] {
            let mut metrics = initial();
            metrics.record_failure(stage, 97);
            assert_eq!(metrics.failed_stage, Some(stage));
            assert_eq!(stage.as_str(), label);
            assert_eq!(serde_json::to_value(stage).unwrap(), json!(label));
            expected["failed_stage"] = json!(label);
            if let Some(field) = changed_field {
                expected[field] = json!(97);
            }
            assert_eq!(
                serde_json::to_value(&metrics).unwrap(),
                expected,
                "{stage:?}"
            );
            expected = serde_json::to_value(initial()).unwrap();
        }
    }

    fn identity(n: u8) -> DevelopmentIdentity {
        DevelopmentIdentity::from_secret_hex(&hex::encode([n; 32])).unwrap()
    }
    fn server() -> PublicServer {
        PublicServer::new(
            identity(71),
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap()
    }
    pub(super) fn shared(mut node: Node) -> Arc<Mutex<Node>> {
        node.enable_local_mempool(crate::PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 64,
            preview_miner: crate::development_public(0).unwrap(),
        })
        .unwrap();
        Arc::new(Mutex::new(node))
    }
    fn hello(op: u8, len: usize) -> Hello {
        Hello {
            op,
            len,
            caller: digest(identity(72).public_key()).unwrap(),
            digest: [3; 32],
            client_nonce: [4; 32],
        }
    }
    // Real authenticated ticket exchange. Returning before the body lets these
    // socket tests hold a bounded grant without invoking any fake work verifier.
    fn paid_grant(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<TcpStream> {
        paid_grant_counted(address, hello, caller, policy).map(|(socket, _)| socket)
    }
    fn paid_grant_counted(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<(TcpStream, [usize; 2])> {
        let (mut socket, cookie, challenge_bytes, deadline) =
            paid_solution_only(address, hello, caller, policy)?;
        let id = cookie.id()?;
        let ready_raw = client_frame(&mut socket, 256, deadline)?;
        let ready: Value = serde_json::from_slice(&ready_raw)?;
        ensure(
            ready["schema"] == "public-body-ready-v3" && ready["cookie_digest"] == hex::encode(id),
            "TEST_READY",
        )?;
        Ok((socket, [challenge_bytes, 4 + ready_raw.len()]))
    }
    pub(super) fn paid_solution_only(
        address: SocketAddr,
        hello: Hello,
        caller: &DevelopmentIdentity,
        policy: PublicPolicy,
    ) -> Result<(TcpStream, Cookie, usize, Instant)> {
        let mut socket = TcpStream::connect(address)?;
        socket.set_nodelay(true)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        client_write(&mut socket, &hello.encode(), deadline)?;
        let raw = client_frame(&mut socket, 2048, deadline)?;
        let challenge_bytes = 4 + raw.len();
        let cookie: Cookie = serde_json::from_slice(&raw)?;
        ensure(cookie.profile == hex::encode(policy.id()), "TEST_PROFILE")?;
        verify_hex_strict(
            identity(71).public_key(),
            &cookie.server_message()?,
            &cookie.signature,
        )
        .map_err(|_| "TEST_SERVER_SIGNATURE")?;
        let id = cookie.id()?;
        let nonce = (0..1_048_576u64)
            .find(|n| winner(id, *n, policy.bits))
            .ok_or("TEST_SOLUTION")?;
        let mut solution = b"PPS3".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(caller.sign(&hash(
                b"public-caller-sign-v3",
                &[&id, &nonce.to_le_bytes()],
            ))?)
            .map_err(|_| "TEST_CALLER_SIGNATURE")?,
        );
        client_write(&mut socket, &solution, deadline)?;
        Ok((socket, cookie, challenge_bytes, deadline))
    }
    fn wait_metric(metrics: &Mutex<PublicMetrics>, predicate: impl Fn(&PublicMetrics) -> bool) {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            if predicate(&metrics.lock().unwrap()) {
                return;
            }
            assert!(Instant::now() < end, "actual reactor observation timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn request_observer_matches_independent_client_received_signed_frame_lengths() {
