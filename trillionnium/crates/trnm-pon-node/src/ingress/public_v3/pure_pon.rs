//! Explicit zero-extra-work public intake. Cookies bind a connection and body;
//! they are neither work receipts nor a separate hashcash admission threshold.
//! Original global CPU, connection, byte, deadline and completion bounds remain.
use super::*;
use trnm_crypto_primitives::pon_work::public_product::PublicProduct;

pub const PROFILE: &str = "public-pure-pon-development-v1";

impl PublicPolicy {
    /// No caller nonce search. A canonical zero nonce acknowledges the signed
    /// cookie; arbitrary callers still undergo the same bounded native checks.
    pub fn pure_pon(lifetime: Duration) -> Result<Self> {
        Self::new(0, lifetime)
    }

    pub fn is_pure_pon(self) -> bool {
        self.bits == 0
    }

    pub fn id(self) -> Hash {
        let original = self.original_resource_id();
        if self.is_pure_pon() {
            hash(b"public-pure-pon-resource-v1", &[
                PROFILE.as_bytes(),
                &original,
                b"canonical-zero-nonce/no-nonce-search/no-hashcash/no-stake/no-caller-allowlist/original-shared-cpu-and-intake-bounds/ops1..5-and9-public-genesis-task-bootstrap-read/known-public-maintenance-exact-product-reject-only-before-raw-submit-replay/all-passing-work-still-full-W1/no-task-authority-cache/no-useful-output-credit",
            ])
        } else {
            original
        }
    }
}

pub(super) fn public_product(policy: PublicPolicy) -> Result<Option<PublicProduct>> {
    if !policy.is_pure_pon() {
        return Ok(None);
    }
    let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
    PublicProduct::new(&a, &b)
        .map(Some)
        .map_err(|error| crate::Error::from(format!("PUBLIC_PRODUCT_SETUP:{error:?}")))
}

/// Retrieve exact public material over the zero-work profile, then verify every
/// field against the miner's pinned genesis before it reaches a producer.
pub fn fetch_public_task_bootstrap(
    address: SocketAddr,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    deadline: Option<Instant>,
) -> (
    Result<crate::public_task_bootstrap::PublicTaskBootstrap>,
    PublicClientMetrics,
) {
    if !policy.is_pure_pon() {
        return (
            Err("PUBLIC_PURE_PON_PROFILE".into()),
            PublicClientMetrics::default(),
        );
    }
    let (reply, metrics) = call_public_protected_v3_with_deadline(
        address,
        &Request::PublicTaskBootstrap,
        settings,
        pinned_server,
        caller,
        policy,
        deadline,
    );
    let result = reply.and_then(|reply| {
        ensure(reply.ok, "PUBLIC_TASK_REMOTE_REFUSED")?;
        let bundle: crate::public_task_bootstrap::PublicTaskBootstrap =
            serde_json::from_value(reply.value)?;
        bundle.validate(settings)?;
        Ok(bundle)
    });
    (result, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_search_profile_has_fresh_identity_and_canonical_acknowledgement() {
        let policy = PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap();
        assert!(policy.is_pure_pon());
        assert_ne!(policy.id(), policy.original_resource_id());
        assert_ne!(policy.id(), PublicPolicy::development().id());
        for cookie in [[0; 32], [255; 32], [37; 32]] {
            assert!(winner(cookie, 0, 0));
            assert!(!winner(cookie, 1, 0));
            assert!(!winner(cookie, u64::MAX, 0));
        }
        for bits in 8..=20 {
            let historical = PublicPolicy::new(bits, Duration::from_secs(2)).unwrap();
            assert_eq!(historical.id(), historical.original_resource_id());
        }
        for bits in 1..8 {
            assert!(PublicPolicy::new(bits, Duration::from_secs(2)).is_err());
        }
        assert!(PublicPolicy::pure_pon(Duration::from_millis(99)).is_err());
        assert!(PublicPolicy::pure_pon(Duration::from_millis(2001)).is_err());
    }

    #[test]
    fn pure_servers_share_original_cpu_and_intake_without_a_new_burst() {
        let policy = PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap();
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([77; 32])).unwrap();
        let first = PublicServer::new_process_cold(identity.clone(), policy).unwrap();
        let domain = first.mutation_cpu_domain();
        let balance = domain.observe().unwrap();
        assert_eq!(balance.stored_credit_ns, 0);
        let second = PublicServer::with_continuous_domain(identity, policy, &domain).unwrap();
        assert!(domain.shares_domain_with(&second.mutation_cpu_domain()));
        assert!(Arc::ptr_eq(
            &first.listener_intake().unwrap(),
            &second.listener_intake().unwrap()
        ));
        assert_eq!(domain.observe().unwrap(), balance);
        assert!(first.public_product.is_some());
        assert!(second.public_product.is_some());
    }

    #[test]
    fn signed_cookies_and_responses_reject_both_cross_namespace_directions() {
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([81; 32])).unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let pure_policy = PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap();
        let old_policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let pure = PublicServer::new_process_cold(identity.clone(), pure_policy).unwrap();
        let mut legacy = PublicServer::new_process_cold(identity.clone(), old_policy).unwrap();
        // Equal owner, keys, epoch and request isolate the resource namespace.
        legacy.secret = pure.secret;
        legacy.epoch = pure.epoch;
        legacy.started = pure.started;
        let body = serde_json::to_vec(&Request::Head).unwrap();
        let hello = Hello {
            op: 2,
            len: body.len(),
            caller: [5; 32],
            digest: hash(b"public-request-body-v3", &[&body]),
            client_nonce: [9; 32],
        };
        let peer = "127.0.0.1:1".parse().unwrap();
        let pure_cookie = pure.cookie(&settings, hello, peer).unwrap();
        let old_cookie = legacy.cookie(&settings, hello, peer).unwrap();
        for (owner, own, foreign, policy) in [
            (&pure, &pure_cookie, &old_cookie, pure_policy),
            (&legacy, &old_cookie, &pure_cookie, old_policy),
        ] {
            owner.validate(own, &settings, true).unwrap();
            assert_eq!(
                owner
                    .validate(foreign, &settings, true)
                    .unwrap_err()
                    .to_string(),
                "PUBLIC_COOKIE_CONTEXT"
            );
            for (cookie, valid) in [(own, true), (foreign, false)] {
                verify_hex_strict(
                    identity.public_key(),
                    &cookie.server_message().unwrap(),
                    &cookie.signature,
                )
                .unwrap();
                assert_eq!(
                    validate_challenge_context(
                        &serde_json::to_vec(cookie).unwrap(),
                        cookie,
                        &hello,
                        &settings,
                        identity.public_key(),
                        policy,
                        policy.id()
                    )
                    .is_ok(),
                    valid
                );
            }
            // A pinned signer signing a foreign profile cannot authorize it.
            let framed = response(owner, &settings, own, Ok(json!({"test":true}))).unwrap();
            let mut reply: Response = serde_json::from_slice(&framed[4..]).unwrap();
            validate_response_context(
                &framed[4..],
                &reply,
                &settings,
                identity.public_key(),
                policy.id(),
                own.id().unwrap(),
                hello.digest,
            )
            .unwrap();
            reply.profile = foreign.profile.clone();
            reply.signature = identity.sign(&reply.message().unwrap()).unwrap();
            verify_hex_strict(
                identity.public_key(),
                &reply.message().unwrap(),
                &reply.signature,
            )
            .unwrap();
            assert_eq!(
                validate_response_context(
                    &serde_json::to_vec(&reply).unwrap(),
                    &reply,
                    &settings,
                    identity.public_key(),
                    policy.id(),
                    own.id().unwrap(),
                    hello.digest
                )
                .unwrap_err()
                .to_string(),
                "PUBLIC_RESPONSE_CONTEXT"
            );
        }
    }

    #[test]
    fn a_pure_client_refuses_a_legacy_cookie_before_acknowledgement_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([82; 32])).unwrap();
        let key = identity.public_key().to_owned();
        let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([83; 32])).unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let legacy = PublicServer::new_process_cold(
            identity,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let (mut stream, peer) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut prefix = [0; 108];
                stream.read_exact(&mut prefix).unwrap();
                let hello = Hello::parse(&prefix).unwrap();
                let cookie = legacy.cookie(&settings, hello, peer).unwrap();
                stream
                    .write_all(&framed(serde_json::to_vec(&cookie).unwrap(), 2048).unwrap())
                    .unwrap();
                let mut byte = [0];
                // EOF, never a legacy ticket or a second protocol preface.
                assert_eq!(stream.read(&mut byte).unwrap(), 0);
            });
            let (reply, metrics) = call_public_protected_v3_with_metrics(
                address,
                &Request::Head,
                &settings,
                &key,
                &caller,
                PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap(),
            );
            assert_eq!(reply.unwrap_err().to_string(), "PUBLIC_CHALLENGE_CONTEXT");
            assert_eq!(metrics.solution_trials, 0);
            assert!(!metrics.solution_found);
            worker.join().unwrap();
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
            );
        });
    }

    #[test]
    fn two_cold_listeners_fetch_mine_reject_attacks_and_admit_without_hashcash() {
        use trnm_crypto_primitives::pon_work;
        let directory = tempfile::tempdir().unwrap();
        let producer_directory = tempfile::tempdir().unwrap();
        let now = super::super::super::now().unwrap();
        let settings = Settings::development_with_profiles(
            Some(now - 100),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
        .unwrap();
        let mut receiver = Node::open(directory.path(), settings.clone(), 1).unwrap();
        receiver
            .enable_local_mempool(crate::PoolLimits {
                max_records: 16,
                max_bytes: 32768,
                max_group_members: 16,
                critical_reserve: 0,
                max_removals: 64,
                preview_miner: crate::development_public(0).unwrap(),
            })
            .unwrap();
        let owner = Arc::new(Mutex::new(receiver));
        let before = owner.lock().unwrap().read_active().unwrap();
        let policy = PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap();
        let first_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
        let second_identity = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
        let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([99; 32])).unwrap();
        let first_key = first_identity.public_key().to_owned();
        let second_key = second_identity.public_key().to_owned();
        let first = PublicServer::new_process_cold(first_identity, policy).unwrap();
        let domain = first.mutation_cpu_domain();
        let second =
            PublicServer::with_continuous_domain(second_identity, policy, &domain).unwrap();
        assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
        let stop = Arc::new(AtomicBool::new(false));
        struct Stop(Arc<AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        thread::scope(|scope| {
            let _guard = Stop(stop.clone());
            let mut addresses = Vec::new();
            let mut workers = Vec::new();
            for server in [first, second] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                addresses.push(listener.local_addr().unwrap());
                let owner = owner.clone();
                let stop = stop.clone();
                workers.push(scope.spawn(move || {
                    serve_public_protected_v3(
                        listener,
                        owner,
                        Duration::from_secs(20),
                        stop,
                        server,
                    )
                }));
            }
            let (bundle, fetch_metrics) = fetch_public_task_bootstrap(
                addresses[0],
                &settings,
                &first_key,
                &caller,
                policy,
                None,
            );
            let bundle = bundle.unwrap();
            assert_eq!(fetch_metrics.solution_trials, 0);
            let producer = Node::open(producer_directory.path(), settings.clone(), 1).unwrap();
            // The miner is a new arbitrary caller, absent from genesis accounts.
            let miner = digest(caller.public_key()).unwrap();
            let packet = producer
                .make_public_bootstrap(&bundle, settings.genesis(), vec![], miner, now - 89, 4096)
                .unwrap();
            let mut false_product = packet.clone();
            let offset = 4 + pon_work::CELLS * 8;
            let old =
                u32::from_le_bytes(false_product.proof[offset..offset + 4].try_into().unwrap());
            let changed = ((u128::from(old) + 1) % pon_work::Q) as u32;
            false_product.proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
            let mut false_trace = packet.clone();
            let offset = pon_work::PROOF_BYTES - 32;
            let trace = (0u64..4096)
                .map(|n| pon_work::hash(b"pure-pon-negative-trace", &[&n.to_le_bytes()]))
                .find(|trace| {
                    trace.as_slice() != &packet.proof[offset..]
                        && pon_work::hash(b"ticket", &[&packet.header.challenge(), trace])
                            <= packet.header.target
                })
                .unwrap();
            false_trace.proof[offset..].copy_from_slice(&trace);
            for (bad, expected) in [
                (false_product, "WORK:Product"),
                (false_trace, "WORK:Transcript"),
            ] {
                let (reply, metrics) = call_public_protected_v3_with_metrics(
                    addresses[0],
                    &Request::Submit {
                        packet: hex::encode(bad.encode().unwrap()),
                    },
                    &settings,
                    &first_key,
                    &caller,
                    policy,
                );
                let reply = reply.unwrap();
                assert!(!reply.ok);
                assert_eq!(reply.solve_trials, 0);
                assert!(reply.value.to_string().contains(expected), "{reply:?}");
                assert_eq!(metrics.solution_trials, 0);
                assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
            }
            let (reply, metrics) = call_public_protected_v3_with_metrics(
                addresses[1],
                &Request::Submit {
                    packet: hex::encode(packet.encode().unwrap()),
                },
                &settings,
                &second_key,
                &caller,
                policy,
            );
            let reply = reply.unwrap();
            assert!(reply.ok);
            assert_eq!(reply.solve_trials, 0);
            assert_eq!(metrics.solution_trials, 0);
            assert_eq!(
                owner.lock().unwrap().active().unwrap().0,
                packet.id().unwrap()
            );
            let flow = domain.observe_actual_flow().unwrap().unwrap();
            assert!(flow.paid_cpu_debit_ns > 0);
            assert_eq!(flow.live_owners, 0);
            assert_eq!(flow.booked_reservation_ns, 0);
            stop.store(true, Ordering::Release);
            for worker in workers {
                worker.join().unwrap().unwrap();
            }
        });
        let final_state = owner.lock().unwrap().read_active().unwrap();
        drop(owner);
        let reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), final_state);
    }
}
