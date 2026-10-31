use super::*;
use trnm_crypto_primitives::pon_work;

fn policy() -> PublicPolicy {
    PublicPolicy::pure_history_raw(Duration::from_secs(2)).unwrap()
}
fn identity(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}
fn enable_pool(node: &mut Node) {
    node.enable_local_mempool(crate::PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: crate::development_public(3).unwrap(),
    })
    .unwrap();
}

#[test]
fn namespace_zero_nonce_and_original_constructors_are_disjoint() {
    let pure = policy();
    assert_eq!(
        hex::encode(pure.id()),
        "bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58"
    );
    let original_pure = PublicPolicy::new(0, Duration::from_secs(2)).unwrap();
    assert!(original_pure.is_pure_pon());
    assert!(!original_pure.is_pure_history_raw());
    assert_ne!(pure.id(), original_pure.id());
    assert!(PublicPolicy::pure_history_raw(Duration::from_millis(99)).is_err());
    assert!(PublicPolicy::pure_history_raw(Duration::from_millis(2001)).is_err());
    assert_ne!(pure.id(), pure.original_resource_id());
    for bits in 8..=20 {
        let old = PublicPolicy::new(bits, Duration::from_secs(2)).unwrap();
        assert_eq!(old.id(), old.original_resource_id());
        assert_ne!(pure.id(), old.id());
    }
    for cookie in [[0; 32], [71; 32], [255; 32]] {
        assert!(winner(cookie, 0, 0));
        assert!(!winner(cookie, 1, 0));
        assert!(!winner(cookie, u64::MAX, 0));
    }
}

#[test]
fn raw_namespace_refuses_filters_caches_and_other_native_profiles() {
    let make = || PublicServer::new(identity(111), policy()).unwrap();
    assert!(make().with_arithmetic_facts().is_err());
    assert!(make()
        .with_w1_rejection_cache(8, Duration::from_secs(1))
        .is_err());
    assert!(make().with_native_growth().is_err());
    assert!(make().with_pure_admission_v2().is_err());
    let server = make();
    assert!(server.arithmetic_facts.is_none() && server.w1_rejection_cache.is_none());
    assert!(server.public_product.is_none() && server.pure_admission_v2.is_none());
    let observed = server.mutation_cpu_domain().observe().unwrap();
    assert_eq!(observed.burst_ns, 2_000_000_000);
    assert_eq!(observed.stored_credit_ns, 2_000_000_000);
    assert_eq!(observed.refill_ns_per_second, 250_000_000);
    assert_eq!(observed.start_reserve_ns, 100_000_000);
    assert_eq!(observed.worker_limit, 2);
}

#[test]
fn explicit_raw_policy_codec_preserves_original_bytes_and_rejects_confusion() {
    let lifetime = Duration::from_secs(2);
    for (bits, expected) in [
        (0, r#"{"bits":0,"lifetime_ms":2000}"#),
        (8, r#"{"bits":8,"lifetime_ms":2000}"#),
        (16, r#"{"bits":16,"lifetime_ms":2000}"#),
    ] {
        let original = PublicPolicy::new(bits, lifetime).unwrap();
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        let decoded: PublicPolicy = serde_json::from_str(expected).unwrap();
        assert_eq!(decoded, original);
        assert!(!decoded.is_pure_history_raw());
        decoded.validate().unwrap();
    }
    let raw = policy();
    let encoded = serde_json::to_string(&raw).unwrap();
    assert_eq!(
        encoded,
        r#"{"bits":0,"lifetime_ms":2000,"admission_variant":"pure-history-raw-v1"}"#
    );
    let decoded: PublicPolicy = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, raw);
    decoded.validate().unwrap();
    let erased: PublicPolicy = serde_json::from_str(r#"{"bits":0,"lifetime_ms":2000}"#).unwrap();
    assert_ne!(erased.id(), raw.id());
    for invalid in [
        r#"{"bits":0,"lifetime_ms":2000,"admission_variant":"pure-v2"}"#,
        r#"{"bits":0,"lifetime_ms":2000,"admission_variant":false}"#,
        r#"{"bits":0,"lifetime_ms":2000,"admission_variant":null}"#,
        r#"{"bits":0,"lifetime_ms":2000,"admission_variant":"pure-history-raw-v1","admission_variant":"standard"}"#,
    ] {
        assert!(serde_json::from_str::<PublicPolicy>(invalid).is_err());
    }
    let wrong_bits: PublicPolicy = serde_json::from_str(
        r#"{"bits":8,"lifetime_ms":2000,"admission_variant":"pure-history-raw-v1"}"#,
    )
    .unwrap();
    assert_eq!(
        wrong_bits.validate().unwrap_err().to_string(),
        "PUBLIC_PURE_HISTORY_RAW_PROFILE"
    );
    assert!(PublicServer::new(identity(120), wrong_bits).is_err());
}

#[test]
fn raw_pure_v1_and_pure_v2_signatures_cannot_cross_exact_namespaces() {
    let lifetime = Duration::from_secs(2);
    let pure = PublicPolicy::pure_pon(lifetime).unwrap();
    let mut servers = [
        PublicServer::new_process_cold(identity(120), policy()).unwrap(),
        PublicServer::new_process_cold(identity(120), pure).unwrap(),
        PublicServer::new_process_cold(identity(120), pure)
            .unwrap()
            .with_pure_admission_v2()
            .unwrap(),
    ];
    let expected = [
        "bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58",
        "f2ab74afd1669afaa28160005d52697f563d690ab8c8a0a1ad34d834b7b5fd3c",
        "f6854cd511f62e47b5d84dcb99b812e0f9df3f6ebe270f5d482933f1ea3bbc56",
    ];
    let (secret, epoch, started) = (servers[0].secret, servers[0].epoch, servers[0].started);
    for (server, pinned) in servers.iter_mut().zip(expected) {
        server.secret = secret;
        server.epoch = epoch;
        server.started = started;
        assert_eq!(hex::encode(server.resource_profile()), pinned);
        assert_eq!(
            server
                .mutation_cpu_domain()
                .observe()
                .unwrap()
                .stored_credit_ns,
            0
        );
    }
    assert!(servers[0].public_product.is_none());
    assert!(servers[1].public_product.is_some());
    assert!(servers[2].public_product.is_some());
    assert!(servers[0].work_arithmetic_facts().is_none());
    assert!(servers[1].work_arithmetic_facts().is_none());
    assert!(servers[2].work_arithmetic_facts().is_some());
    // Rejection caching must not be silently attached to any signed pure mode.
    for server in [
        PublicServer::new_process_cold(identity(120), pure).unwrap(),
        PublicServer::new_process_cold(identity(120), pure)
            .unwrap()
            .with_pure_admission_v2()
            .unwrap(),
    ] {
        assert!(server
            .with_w1_rejection_cache(8, Duration::from_secs(1))
            .is_err());
    }
    let settings = Settings::development(Some(1)).unwrap();
    let body = serde_json::to_vec(&Request::Head).unwrap();
    let hello = Hello {
        op: 2,
        len: body.len(),
        caller: [3; 32],
        digest: hash(b"public-request-body-v3", &[&body]),
        client_nonce: [7; 32],
    };
    let peer = "127.0.0.1:1".parse().unwrap();
    let cookies: Vec<_> = servers
        .iter()
        .map(|server| server.cookie(&settings, hello, peer).unwrap())
        .collect();
    for (index, server) in servers.iter().enumerate() {
        for (other, cookie) in cookies.iter().enumerate() {
            verify_hex_strict(
                identity(120).public_key(),
                &cookie.server_message().unwrap(),
                &cookie.signature,
            )
            .unwrap();
            assert_eq!(
                server.validate(cookie, &settings, true).is_ok(),
                index == other
            );
            assert_eq!(
                validate_challenge_context(
                    &serde_json::to_vec(cookie).unwrap(),
                    cookie,
                    &hello,
                    &settings,
                    identity(120).public_key(),
                    server.policy,
                    server.resource_profile(),
                )
                .is_ok(),
                index == other,
            );
        }
        let own = &cookies[index];
        let frame = response(server, &settings, own, Ok(json!({"test":true}))).unwrap();
        let mut reply: Response = serde_json::from_slice(&frame[4..]).unwrap();
        for (other, cookie) in cookies.iter().enumerate() {
            // Re-signing under the same real key cannot cross the pinned mode.
            reply.profile = cookie.profile.clone();
            reply.signature = identity(120).sign(&reply.message().unwrap()).unwrap();
            assert_eq!(
                validate_response_context(
                    &serde_json::to_vec(&reply).unwrap(),
                    &reply,
                    &settings,
                    identity(120).public_key(),
                    server.resource_profile(),
                    own.id().unwrap(),
                    hello.digest,
                )
                .is_ok(),
                index == other,
            );
        }
    }
}

#[test]
fn real_tcp_zero_search_full_w1_refusals_admission_and_cold_state_readback() {
    // Component control only: the fixed-cgroup History campaign is a separate
    // ignored selector. This test does not substitute an in-process importer.
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
    enable_pool(&mut node);
    let before = node.read_active().unwrap();
    let valid = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 2,
            4096,
        )
        .unwrap();
    WorkCheckedPacket::verify(valid.clone()).unwrap();
    let mut false_product = valid.clone();
    let position = 4 + 2 * pon_work::CELLS * 4;
    let word = u32::from_le_bytes(
        false_product.proof[position..position + 4]
            .try_into()
            .unwrap(),
    );
    false_product.proof[position..position + 4]
        .copy_from_slice(&(((u128::from(word) + 1) % pon_work::Q) as u32).to_le_bytes());
    let mut false_trace = valid.clone();
    let position = false_trace.proof.len() - 32;
    let challenge = valid.header.challenge();
    let tail = (0_u64..4096)
        .map(|nonce| {
            hash(
                b"pure-history-negative-trace-v1",
                &[&challenge, &nonce.to_le_bytes()],
            )
        })
        .find(|tail| {
            tail.as_slice() != &valid.proof[position..]
                && hash(b"ticket", &[&challenge, tail]) <= valid.header.target
        })
        .unwrap();
    false_trace.proof[position..].copy_from_slice(&tail);
    let owner = Arc::new(Mutex::new(node));
    let server = PublicServer::new(identity(112), policy()).unwrap();
    let key = server.identity.public_key().to_owned();
    let domain = server.mutation_cpu_domain();
    let caller = identity(113);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Mutex::new(PublicMetrics::default()));
    let observer = PublicRequestObserver::new(64).unwrap();
    thread::scope(|scope| {
        let (node, signal, metrics, observed) = (
            owner.clone(),
            stop.clone(),
            counters.clone(),
            observer.clone(),
        );
        let worker = scope.spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                node,
                Duration::from_secs(15),
                signal,
                server,
                metrics,
                observed,
            )
        });
        for (packet, expected) in [
            (false_trace, "WORK:Transcript"),
            (false_product, "WORK:Product"),
        ] {
            let (reply, metrics, ack) = call_public_pure_history_raw(
                address,
                &Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &settings,
                &key,
                &caller,
                policy(),
                Some(Instant::now() + Duration::from_secs(2)),
            );
            let reply = reply.unwrap();
            assert!(!reply.ok);
            assert_eq!(reply.value["error"], expected);
            assert_eq!(reply.solve_trials, 0);
            assert_eq!(metrics.solution_trials, 0);
            assert_eq!(metrics.solution_search_ns, 0);
            assert_eq!(ack.search_budget, 0);
            assert_eq!(ack.solution_nonce, Some(0));
            assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        }
        let (reply, metrics, ack) = call_public_pure_history_raw(
            address,
            &Request::Submit {
                packet: hex::encode(valid.encode().unwrap()),
            },
            &settings,
            &key,
            &caller,
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(reply.unwrap().ok);
        assert_eq!(metrics.solution_trials, 0);
        assert_eq!(ack.solution_nonce, Some(0));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
    });
    let rows = observer.snapshot().records;
    let submitted: Vec<_> = rows
        .iter()
        .filter(|r| r.operation == Some(1) && r.dispatch_started)
        .collect();
    assert_eq!(submitted.len(), 3);
    assert!(submitted
        .iter()
        .all(|r| r.full_work_started && r.full_work_thread_cpu_ns.is_some_and(|n| n > 0)));
    assert_eq!(
        submitted
            .iter()
            .filter(|r| r.full_work_accepted == Some(true))
            .count(),
        1
    );
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert!(flow.balance_identity_verified && flow.paid_cpu_debit_ns > 0);
    assert_eq!(flow.live_owners, 0);
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
    let final_state = owner.lock().unwrap().read_active().unwrap();
    assert_eq!(final_state.0, valid.id().unwrap());
    drop(owner);
    let reopened = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), final_state);
}

#[test]
fn real_tcp_clients_refuse_both_cross_profile_directions_before_acknowledgement() {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let old = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    for (server_policy, client_policy) in [(policy(), old), (old, policy())] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
        enable_pool(&mut node);
        let owner = Arc::new(Mutex::new(node));
        let server = PublicServer::new(identity(114), server_policy).unwrap();
        let key = server.identity.public_key().to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        thread::scope(|scope| {
            let (owner, signal) = (owner.clone(), stop.clone());
            let worker = scope.spawn(move || {
                serve_public_protected_v3(listener, owner, Duration::from_secs(5), signal, server)
            });
            let (reply, metrics) = call_public_protected_v3_with_deadline(
                address,
                &Request::Head,
                &settings,
                &key,
                &identity(115),
                client_policy,
                Some(Instant::now() + Duration::from_secs(1)),
            );
            assert_eq!(reply.unwrap_err().to_string(), "PUBLIC_CHALLENGE_CONTEXT");
            assert_eq!(metrics.solution_trials, 0);
            assert!(!metrics.solution_found);
            assert_eq!(metrics.failed_stage, Some(PublicClientStage::Challenge));
            stop.store(true, Ordering::Release);
            worker.join().unwrap().unwrap();
        });
    }
}

#[test]
fn real_tcp_nonzero_signed_acknowledgement_cannot_reach_a_request_body() {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    enable_pool(&mut node);
    let owner = Arc::new(Mutex::new(node));
    let server = PublicServer::new(identity(116), policy()).unwrap();
    let caller = identity(117);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Mutex::new(PublicMetrics::default()));
    let observer = PublicRequestObserver::new(8).unwrap();
    thread::scope(|scope| {
        let (signal, counters, observed) = (stop.clone(), counters.clone(), observer.clone());
        let worker = scope.spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_secs(5),
                signal,
                server,
                counters,
                observed,
            )
        });
        let body = serde_json::to_vec(&Request::Head).unwrap();
        let hello = Hello {
            op: 2,
            len: body.len(),
            caller: digest(caller.public_key()).unwrap(),
            digest: hash(b"public-request-body-v3", &[&body]),
            client_nonce: [7; 32],
        };
        let mut stream = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client_write(&mut stream, &hello.encode(), deadline).unwrap();
        let cookie: Cookie =
            serde_json::from_slice(&client_frame(&mut stream, 2048, deadline).unwrap()).unwrap();
        assert_eq!(cookie.bits, 0);
        let id = cookie.id().unwrap();
        let nonce = 1_u64;
        let mut solution = b"PPS3".to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        solution.extend(
            hex::decode(
                caller
                    .sign(&hash(
                        b"public-caller-sign-v3",
                        &[&id, &nonce.to_le_bytes()],
                    ))
                    .unwrap(),
            )
            .unwrap(),
        );
        client_write(&mut stream, &solution, deadline).unwrap();
        assert!(client_frame(&mut stream, 2048, deadline).is_err());
        drop(stream);
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
    });
    assert_eq!(counters.lock().unwrap().ticket_refusals, 1);
    assert!(observer
        .snapshot()
        .records
        .iter()
        .all(|row| !row.dispatch_started));
}

#[test]
fn real_tcp_same_signer_cannot_substitute_a_foreign_response_profile() {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let server = PublicServer::new(identity(118), policy()).unwrap();
    let key = server.identity.public_key().to_owned();
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (mut stream, peer) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut prefix = [0; 108];
            stream.read_exact(&mut prefix).unwrap();
            let hello = Hello::parse(&prefix).unwrap();
            let cookie = server.cookie(&settings, hello, peer).unwrap();
            stream
                .write_all(&framed(serde_json::to_vec(&cookie).unwrap(), 2048).unwrap())
                .unwrap();
            let mut solution = [0; 108];
            stream.read_exact(&mut solution).unwrap();
            assert_eq!(&solution[..4], b"PPS3");
            assert_eq!(u64::from_le_bytes(solution[36..44].try_into().unwrap()), 0);
            stream.write_all(&framed(serde_json::to_vec(&json!({
                "schema":"public-body-ready-v3","cookie_digest":hex::encode(cookie.id().unwrap())
            })).unwrap(), 256).unwrap()).unwrap();
            let mut body = vec![0; hello.len];
            stream.read_exact(&mut body).unwrap();
            let original =
                response(&server, &settings, &cookie, Ok(json!({"head":"fixture"}))).unwrap();
            let mut reply: Response = serde_json::from_slice(&original[4..]).unwrap();
            reply.profile = hex::encode(PublicPolicy::new(8, Duration::from_secs(2)).unwrap().id());
            reply.signature = server.identity.sign(&reply.message().unwrap()).unwrap();
            verify_hex_strict(&key, &reply.message().unwrap(), &reply.signature).unwrap();
            stream
                .write_all(&framed(serde_json::to_vec(&reply).unwrap(), 2048).unwrap())
                .unwrap();
        });
        let (reply, metrics, acknowledgement) = call_public_pure_history_raw(
            address,
            &Request::Head,
            &settings,
            &key,
            &identity(119),
            policy(),
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert_eq!(reply.unwrap_err().to_string(), "PUBLIC_RESPONSE_CONTEXT");
        assert_eq!(metrics.solution_trials, 0);
        assert_eq!(acknowledgement.solution_nonce, Some(0));
        worker.join().unwrap();
    });
}
