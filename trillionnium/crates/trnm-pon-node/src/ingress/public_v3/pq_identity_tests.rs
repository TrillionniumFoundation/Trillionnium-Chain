use super::*;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

fn identity(n: u8) -> PqPublicIdentity {
    let seed = Zeroizing::new([n; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqPublicIdentity::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap()).unwrap()
}
fn hello(caller: &PqPublicIdentity) -> Hello {
    Hello {
        op: 2,
        len: 13,
        caller: digest(caller.public_key()).unwrap(),
        digest: [3; 32],
        client_nonce: [4; 32],
    }
}
fn server() -> PublicServer {
    PublicServer::new_pq_history(
        identity(71),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}

#[test]
fn pq_response_reservation_owns_both_slots_and_signs_once_on_its_actual_thread() {
    let owner = server();
    let intake = owner.listener_intake().unwrap();
    let response = owner.reserve_response_signing(&intake).unwrap();
    let unused = owner.reserve_response_signing(&intake).unwrap();
    let pending = intake.pq_authentication.usage().unwrap();
    assert_eq!(pending.in_flight, 2);
    assert_eq!(pending.pending_response_signatures, 2);
    assert_eq!(pending.reserved_cpu_ns, 2 * MUTATION_CPU_START_RESERVE_NS);
    assert_eq!(pending.known_intervals, 0);
    assert_eq!(pending.actual_thread_cpu_ns, 0);
    assert!(owner
        .sign_authentication(&[4; 32])
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuBudget));
    let mut message = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".to_vec();
    message.extend_from_slice(&[7; 48]);
    let signature = thread::scope(|scope| {
        scope
            .spawn(|| response.sign(&owner, &message))
            .join()
            .unwrap()
            .unwrap()
    });
    let key = identity(71);
    let verifier =
        PqNativeVerifier::from_pinned_spki(key.public_spki(), digest(key.public_key()).unwrap())
            .unwrap();
    verifier
        .verify_exact_message(&message, &hex::decode(signature).unwrap())
        .unwrap();
    drop(unused);
    let after = intake.pq_authentication.usage().unwrap();
    assert_eq!(after.attempts, 2);
    assert_eq!(after.bytes, 2 * message.len() as u64);
    assert_eq!(after.known_intervals, 1);
    assert!(after.actual_thread_cpu_ns > 0);
    assert_eq!(after.unknown_intervals, 0);
    assert_eq!(after.in_flight, 0);
    assert_eq!(after.pending_response_signatures, 0);
    assert_eq!(after.reserved_cpu_ns, 0);
    assert_eq!(after.unused_response_reservations, 1);
    assert!(!after.unavailable);
}

#[test]
fn pq_response_reservation_owns_final_attempt_and_bytes_without_second_admission() {
    let budget = AuthenticationBudget::default();
    let mut message = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".to_vec();
    message.extend_from_slice(&[8; 48]);
    // Controlled near-limit state, not a claim of 8191 measured signatures.
    {
        let mut state = budget.usage.lock().unwrap();
        state.attempts = MAX_AUTHENTICATIONS - 1;
        state.bytes = MAX_AUTHENTICATED_BYTES - message.len() as u64;
    }
    let response = budget.reserve_response().unwrap();
    assert!(budget
        .perform(1, || Ok(()))
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuBudget));
    let key = identity(74);
    let signature = response.perform(|| key.sign(&message)).unwrap();
    let verifier =
        PqNativeVerifier::from_pinned_spki(key.public_spki(), digest(key.public_key()).unwrap())
            .unwrap();
    verifier
        .verify_exact_message(&message, &hex::decode(signature).unwrap())
        .unwrap();
    let after = budget.usage().unwrap();
    assert_eq!(after.attempts, MAX_AUTHENTICATIONS);
    assert_eq!(after.bytes, MAX_AUTHENTICATED_BYTES);
    assert_eq!(after.known_intervals, 1);
    assert_eq!(after.in_flight, 0);
    assert!(budget.reserve_response().is_err());
}

#[test]
fn pq_response_reservation_refuses_each_original_lifetime_limit_before_crypto() {
    for boundary in [0, 1, 2] {
        let budget = AuthenticationBudget::default();
        {
            let mut state = budget.usage.lock().unwrap();
            // Deliberate boundary injection; these are not measured totals.
            match boundary {
                0 => state.attempts = MAX_AUTHENTICATIONS,
                1 => state.bytes = MAX_AUTHENTICATED_BYTES,
                _ => {
                    state.actual_thread_cpu_ns =
                        MAX_AUTHENTICATION_CPU_NS - MUTATION_CPU_START_RESERVE_NS + 1
                }
            }
        }
        let before = budget.usage().unwrap();
        assert!(budget.reserve_response().is_err());
        let after = budget.usage().unwrap();
        assert_eq!(after.attempts, before.attempts);
        assert_eq!(after.bytes, before.bytes);
        assert_eq!(after.actual_thread_cpu_ns, before.actual_thread_cpu_ns);
        assert_eq!(after.in_flight, 0);
        assert_eq!(after.reserved_cpu_ns, 0);
    }
}

#[test]
fn pq_response_reservation_unknown_finish_or_unwind_never_refunds_principal() {
    for unwind in [false, true] {
        let budget = AuthenticationBudget::default();
        let response = budget.reserve_response().unwrap();
        if unwind {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = response;
                panic!("controlled native unwind before PQ response");
            }))
            .is_err());
        } else {
            budget.fail_next_finish_for_test();
            let key = identity(75);
            let mut message = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".to_vec();
            message.extend_from_slice(&[6; 48]);
            assert!(response
                .perform(|| key.sign(&message))
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        }
        let after = budget.usage().unwrap();
        assert!(after.unavailable);
        assert_eq!(after.attempts, 1);
        assert_eq!(after.in_flight, 0);
        assert_eq!(after.pending_response_signatures, 0);
        assert_eq!(after.reserved_cpu_ns, MUTATION_CPU_START_RESERVE_NS);
        assert_eq!(after.unknown_intervals, u64::from(!unwind));
        let called = AtomicBool::new(false);
        assert!(budget
            .perform(1, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        assert!(!called.load(Ordering::Acquire));
    }
}

#[test]
fn pq_response_reservation_measured_lifetime_overrun_denies_signature_and_fences_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let original_state = node.read_active().unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    let intake = domain.shared_budget().lock().unwrap().intake.clone();
    let response = intake.pq_authentication.reserve_response().unwrap();
    // Actual CPU inside a deliberately expensive interval, not simulated
    // elapsed time and not a claim about normal ML-DSA performance.
    intake
        .pq_authentication
        .perform(1, || {
            let stamp = ThreadCpuStamp::start().unwrap();
            let deadline = Instant::now() + Duration::from_millis(WORK_MS);
            let mut value = 1u64;
            loop {
                for _ in 0..100_000 {
                    value = std::hint::black_box(
                        value.wrapping_mul(6364136223846793005).wrapping_add(1),
                    );
                }
                if stamp.clone().finish().unwrap() > MAX_AUTHENTICATION_CPU_NS {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "original finite test CPU window exhausted"
                );
            }
            Ok(())
        })
        .unwrap();
    let debt = intake.pq_authentication.usage().unwrap();
    assert!(debt.actual_thread_cpu_ns > MAX_AUTHENTICATION_CPU_NS);
    assert!(!debt.unavailable);
    let called = AtomicBool::new(false);
    assert!(response
        .perform(|| {
            called.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuBudget));
    assert!(!called.load(Ordering::Acquire));
    let after = intake.pq_authentication.usage().unwrap();
    assert_eq!(after.in_flight, 0);
    assert_eq!(after.reserved_cpu_ns, 0);
    assert!(after.stored_credit_ns < 0);
    assert_eq!(after.unknown_intervals, 0);
    assert!(!domain.public_epoch_is_settled().unwrap());
    node.finish_ordinary_public_service_epoch(true).unwrap();
    assert_eq!(node.read_active().unwrap(), original_state);
    assert!(node
        .bind_public_service_cpu_domain(&domain)
        .unwrap_err()
        .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    drop(node);
    let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), original_state);
    assert!(reopened
        .bind_public_service_cpu_domain(&ServiceMutationCpuDomain::standalone())
        .unwrap_err()
        .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
}

#[test]
fn pq_response_reservation_controlled_known_debt_prevents_continuous_clean_close() {
    // Existing unqualified owner/journal mechanism fixture; not production
    // attestation or a measured CPU-overrun observation.
    let (_native, directory, node) = Node::continuous_authentication_guard_fixture();
    let before = node.continuous_journal_head().unwrap();
    let state = node.read_active().unwrap();
    let domain = node.continuous_cpu_domain().unwrap();
    let intake = domain.shared_budget().lock().unwrap().intake.clone();
    intake
        .pq_authentication
        .usage
        .lock()
        .unwrap()
        .actual_thread_cpu_ns = MAX_AUTHENTICATION_CPU_NS + 1;
    assert!(!domain.public_epoch_is_settled().unwrap());
    assert!(node
        .close_continuous_checkpoint()
        .unwrap_err()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert_eq!(node.continuous_journal_head().unwrap(), before);
    assert_eq!(node.read_active().unwrap(), state);
    assert!(directory.path().join("unavailable.json").exists());
}

#[test]
fn pq_only_account_profile_rejects_classical_public_v3_client_before_connection() {
    use std::collections::BTreeSet;
    use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
        application_v6::ApplicationPolicy, GenesisAccount,
    };
    let now = crate::ingress::now().unwrap();
    let accounts: Vec<_> = [81u8, 82, 83]
        .into_iter()
        .map(|n| GenesisAccount {
            spki: identity(n).public_spki().to_vec(),
            balance: 1_000_000,
        })
        .collect();
    let policy = ApplicationPolicy {
        evaluators: accounts
            .iter()
            .take(2)
            .map(|account| ml_dsa_65_key_id_from_spki(&account.spki).unwrap())
            .collect::<BTreeSet<_>>(),
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
    };
    let settings = Settings::native_pq_application_v6(&accounts, now - 100, &policy).unwrap();
    let classical = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
    // TCP port zero has no server. Any IO error instead of the exact profile
    // refusal would prove the client reached a network operation too early.
    let unopened: SocketAddr = "127.0.0.1:0".parse().unwrap();
    for request in [
        Request::Head,
        Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        },
    ] {
        let (result, metrics) = call_public_protected_v3_with_deadline(
            unopened,
            &request,
            &settings,
            classical.public_key(),
            &classical,
            PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
            None,
        );
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("AUTH_CLASSICAL_FOR_PQ_PROFILE"),
            "{error}"
        );
        assert_eq!(metrics.failed_stage, Some(PublicClientStage::Construction));
        assert_eq!(metrics.solution_trials, 0);
        assert!(!metrics.solution_found);
    }
    // The existing classical development client still proceeds to local
    // socket IO (and rejects this deliberately unopened destination).
    let classic = Settings::development(Some(now - 100)).unwrap();
    let (result, metrics) = call_public_protected_v3_with_deadline(
        unopened,
        &Request::Head,
        &classic,
        classical.public_key(),
        &classical,
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        None,
    );
    let error = result.unwrap_err();
    assert!(!error.to_string().contains("AUTH_CLASSICAL_FOR_PQ_PROFILE"));
    assert_eq!(metrics.failed_stage, Some(PublicClientStage::Challenge));
}

#[test]
fn pq_history_real_three_party_messages_are_strict_and_old_wire_is_refused() {
    let settings = Settings::development(Some(1)).unwrap();
    let caller = identity(72);
    let owner = server();
    let h = hello(&caller);
    assert_eq!(h.encode_for(true).len(), HELLO_BYTES);
    assert!(Hello::parse_for(&h.encode_for(false), true).is_err());
    assert!(Hello::parse_for(&h.encode_for(true), false).is_err());
    let cookie = owner
        .cookie(&settings, h, "127.0.0.1:1".parse().unwrap())
        .unwrap();
    let server_key = identity(71);
    let pin = ServerPin::Pq {
        key_id: server_key.public_key().into(),
        verifier: Box::new(
            PqNativeVerifier::from_pinned_spki(
                server_key.public_spki(),
                digest(server_key.public_key()).unwrap(),
            )
            .unwrap(),
        ),
    };
    let raw = serde_json::to_vec(&cookie).unwrap();
    assert!(raw.len() > 2048 && raw.len() <= challenge_maximum(true));
    validate_challenge_context_authenticated(
        &raw,
        &cookie,
        &h,
        &settings,
        &pin,
        owner.policy,
        owner.policy.pq_history_id(),
    )
    .unwrap();
    assert!(validate_challenge_context(
        &raw,
        &cookie,
        &h,
        &settings,
        server_key.public_key(),
        owner.policy,
        owner.policy.pq_history_id()
    )
    .is_err());
    let nonce = 23u64;
    let mut solution = solution_magic(true).to_vec();
    solution.extend(cookie.id().unwrap());
    solution.extend(nonce.to_le_bytes());
    solution.extend(caller.public_spki());
    solution.extend(
        hex::decode(
            caller
                .sign(&caller_message(&cookie, nonce, true).unwrap())
                .unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(solution.len(), PQ_SOLUTION_BYTES);
    owner.verify_caller(&cookie, nonce, &solution).unwrap();
    solution[PQ_SOLUTION_BYTES - 1] ^= 1;
    assert!(owner.verify_caller(&cookie, nonce, &solution).is_err());
    let usage = owner
        .listener_intake()
        .unwrap()
        .pq_authentication
        .usage()
        .unwrap();
    assert_eq!(usage.attempts, 3); // Cookie, accepted caller, rejected caller.
    assert!(usage.actual_thread_cpu_ns > 0);
    let intake = owner.listener_intake().unwrap();
    let mut signing = Some(owner.reserve_response_signing(&intake).unwrap());
    let bytes = response(
        &owner,
        &settings,
        &cookie,
        Ok(json!({"head":"fixture"})),
        &mut signing,
        &|| Ok(()),
    )
    .unwrap();
    let response: Response = serde_json::from_slice(&bytes[4..]).unwrap();
    pin.verify(&response.message().unwrap(), &response.signature)
        .unwrap();
    let mut old = cookie.clone();
    old.schema = "public-resource-cookie-v3".into();
    assert!(owner.validate(&old, &settings, true).is_err());
    assert!(pin
        .verify(&old.server_message().unwrap(), &old.signature)
        .is_err());
    assert!(owner
        .cookie(
            &settings,
            Hello { op: 1, ..h },
            "127.0.0.1:1".parse().unwrap()
        )
        .is_err());
}

#[test]
fn pq_history_failure_budget_and_listener_reconstruction_share_the_original_epoch() {
    let first = server();
    let domain = first.mutation_cpu_domain();
    let second =
        PublicServer::with_continuous_pq_history(identity(73), first.policy, &domain).unwrap();
    let a = first.listener_intake().unwrap();
    let b = second.listener_intake().unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    for _ in 0..MAX_AUTHENTICATIONS {
        assert!(a
            .pq_authentication
            .perform::<()>(1, || Err("PUBLIC_CALLER_SIGNATURE".into()))
            .is_err());
    }
    let usage = b.pq_authentication.usage().unwrap();
    assert_eq!(usage.attempts, MAX_AUTHENTICATIONS);
    assert_eq!(usage.bytes, MAX_AUTHENTICATIONS);
    assert!(second
        .sign_authentication(b"no refund after failed authentication")
        .is_err());
    assert_eq!(
        b.pq_authentication.usage().unwrap().attempts,
        MAX_AUTHENTICATIONS
    );
    let budget = AuthenticationBudget::default();
    budget
        .perform(MAX_AUTHENTICATED_BYTES as usize, || Ok(()))
        .unwrap();
    assert!(budget.perform(1, || Ok(())).is_err());
    assert_eq!(budget.usage().unwrap().attempts, 1);
    let interrupted = AuthenticationBudget::default();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = interrupted.perform::<()>(1, || panic!("incomplete authentication CPU interval"));
    }));
    assert!(panic.is_err());
    assert!(interrupted.usage().unwrap().unavailable);
    assert_eq!(interrupted.usage().unwrap().attempts, 1);
    assert!(interrupted.perform(1, || Ok(())).is_err());
}

#[test]
fn pq_history_original_listener_reads_real_owner_and_classical_clients_cannot_downgrade() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let owner = super::super::tests::shared(node);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let service = server();
    let policy = service.policy;
    let worker = thread::spawn(move || {
        serve_public_protected_v3(listener, owner, Duration::from_secs(10), stopping, service)
    });
    let server_key = identity(71);
    let caller = identity(72);
    let expected_id = digest(server_key.public_key()).unwrap();
    let (head, observed) = call_public_history_pq_v4(
        address,
        &Request::Head,
        &settings,
        server_key.public_spki(),
        expected_id,
        &caller,
        policy,
        None,
    );
    assert!(head.unwrap().ok);
    assert!(observed.solution_found);
    let (history, _) = call_public_history_pq_v4(
        address,
        &Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        },
        &settings,
        server_key.public_spki(),
        expected_id,
        &caller,
        policy,
        None,
    );
    assert!(history.unwrap().ok);
    let classic = DevelopmentIdentity::from_secret_hex(&"72".repeat(32)).unwrap();
    assert!(call_public_protected_v3(
        address,
        &Request::Head,
        &settings,
        server_key.public_key(),
        &classic,
        policy
    )
    .is_err());
    let (wrong_pin, wrong_metrics) = call_public_history_pq_v4(
        address,
        &Request::Head,
        &settings,
        server_key.public_spki(),
        [0; 32],
        &caller,
        policy,
        None,
    );
    assert!(wrong_pin.is_err());
    assert!(!wrong_metrics.solution_found);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap().unwrap();
    assert_eq!(metrics.completed_read, 2);
    assert_eq!(metrics.completed_submit, 0);
    assert_eq!(metrics.completed_pool_submit, 0);
    assert_eq!(metrics.pq_authentication_attempts, 6);
    assert!(metrics.pq_authentication_thread_cpu_ns > 0);
    assert_eq!(metrics.unknown_caller_durable_rows, 0);
    assert_eq!(metrics.read_grants_after_shutdown, 0);
    assert_eq!(metrics.output_reserved_bytes_after_shutdown, 0);
}

#[test]
fn pq_history_native_application_account_packet_uses_the_same_paid_history_owner() {
    use std::collections::BTreeSet;
    use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
        application_v6::ApplicationPolicy, GenesisAccount,
    };
    let directory = tempfile::tempdir().unwrap();
    let now = crate::ingress::now().unwrap();
    let accounts: Vec<_> = [81u8, 82, 83]
        .into_iter()
        .map(|n| GenesisAccount {
            spki: identity(n).public_spki().to_vec(),
            balance: 1_000_000,
        })
        .collect();
    let evaluators: BTreeSet<_> = accounts
        .iter()
        .take(2)
        .map(|a| ml_dsa_65_key_id_from_spki(&a.spki).unwrap())
        .collect();
    let policy = ApplicationPolicy {
        evaluators,
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
    };
    let settings = Settings::native_pq_application_v6(&accounts, now - 100, &policy).unwrap();
    let server_key = identity(71);
    let caller = identity(72);
    let network = crate::ingress::pq_network::PqNetworkPolicy::new(
        &settings,
        server_key.public_spki(),
        1,
        [caller.public_spki().to_vec()],
    )
    .unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &network).unwrap();
    let miner = ml_dsa_65_key_id_from_spki(&accounts[0].spki).unwrap();
    let transaction = {
        use trnm_protocol::pq_native_accounts_v2::{self as wire, AccountProfile};
        let profile = AccountProfile::ApplicationV6;
        let common = wire::Common {
            context: wire::ChainContext {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            account: miner,
            nonce: 1,
            expires_at: now + 300,
            max_fee: 100_000,
            generation: 1,
        };
        let keys = [wire::WitnessKey {
            role: 1,
            generation: 1,
            key_id: miner,
            spki: None,
        }];
        let mut payload = ml_dsa_65_key_id_from_spki(&accounts[1].spki)
            .unwrap()
            .to_vec();
        payload.extend(7_u64.to_le_bytes());
        payload.extend(0_u16.to_be_bytes());
        let statement =
            wire::signing_statement_for_profile(profile, &common, 1, &payload, &keys, 0).unwrap();
        let signature = identity(81).key.sign_exact_message(&statement).unwrap();
        let mut frame = statement.to_vec();
        frame.extend((signature.len() as u16).to_be_bytes());
        frame.extend(signature);
        wire::encode_for_profile(profile, &common, 1, &payload, &keys, &[frame]).unwrap()
    };
    assert!(transaction.len() > 2048);
    let packet = node
        .make_consensus_maintenance(settings.genesis(), vec![transaction], miner, now - 50, 4096)
        .unwrap();
    let completed = crate::store::WorkCheckedPacket::verify(packet.clone()).unwrap();
    assert!(completed.completion_identity().is_err());
    assert!(completed
        .completion_identity_for_context(&settings.packet_codec_context())
        .is_ok());
    assert!(completed
        .completion_identity_for_context(
            &Settings::development(Some(1))
                .unwrap()
                .packet_codec_context(),
        )
        .is_err());
    let block = node.admit(&packet, now).unwrap();
    node.activate(block).unwrap();
    let expected_packet = packet.encode_for_settings(&settings).unwrap();
    assert!(expected_packet.starts_with(b"PQP6"));
    let codec = settings.packet_codec_context();
    assert_eq!(
        completed.completion_identity_for_context(&codec).unwrap(),
        trnm_protocol::pon_wire::hash(
            b"public-pq-history-complete-work-identity-v1",
            &[&expected_packet],
        )
    );
    assert_eq!(
        crate::ingress::hex_packet_for_context(&hex::encode(&expected_packet), &codec)
            .unwrap()
            .encode_for_settings(&settings)
            .unwrap(),
        expected_packet
    );
    let mut changed = settings.clone();
    changed.app.params["native_pq_v2_anchor"] = serde_json::json!("changed");
    let changed_codec = changed.packet_codec_context();
    assert_eq!(
        crate::ingress::hex_packet_for_context("x", &changed_codec)
            .unwrap_err()
            .to_string(),
        "PACKET_HEX"
    );
    let changed_error = crate::Packet::decode_for_settings(&expected_packet, &changed)
        .unwrap_err()
        .to_string();
    assert_eq!(changed_error, "PQ2_CONFIG_CHANGED");
    for _ in 0..2 {
        assert_eq!(
            crate::ingress::hex_packet_for_context(&hex::encode(&expected_packet), &changed_codec)
                .unwrap_err()
                .to_string(),
            changed_error
        );
        assert_eq!(
            completed
                .completion_identity_for_context(&changed_codec)
                .unwrap_err()
                .to_string(),
            changed_error
        );
    }
    let owner = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let service = server();
    let transport = service.policy;
    let worker = thread::spawn(move || {
        serve_public_protected_v3(listener, owner, Duration::from_secs(10), stopping, service)
    });
    let (reply, _) = call_public_history_pq_v4(
        address,
        &Request::History {
            tip: hex::encode(block),
            after: hex::encode(settings.genesis()),
        },
        &settings,
        server_key.public_spki(),
        digest(server_key.public_key()).unwrap(),
        &caller,
        transport,
        None,
    );
    let reply = reply.unwrap();
    assert!(reply.ok);
    assert_eq!(reply.value["schema"], "pon-native-pq-history-v6");
    let packets = reply.value["packets"].as_array().unwrap();
    assert_eq!(packets.len(), 1);
    let actual = hex::decode(packets[0].as_str().unwrap()).unwrap();
    assert_eq!(actual, expected_packet);
    assert_eq!(
        crate::Packet::decode_for_settings(&actual, &settings)
            .unwrap()
            .id()
            .unwrap(),
        block
    );
    assert!(crate::Packet::decode(&actual).is_err());
    // The received page enters the same paid importer, including its original
    // durable CPU epoch and complete W1/M06 admission. A classic page label
    // cannot make the new namespace choose its former packet decoder.
    let destination = tempfile::tempdir().unwrap();
    let mut destination_node =
        Node::open_with_pq_network(destination.path(), settings.clone(), 1, &network).unwrap();
    let mut classic_page: crate::ingress::Page =
        serde_json::from_value(reply.value.clone()).unwrap();
    classic_page.schema = "pon-native-history-v1".into();
    assert!(crate::ingress::receive_page_from(
        &mut destination_node,
        address,
        classic_page,
        block,
        settings.genesis(),
        now,
    )
    .is_err());
    assert!(destination_node.public_service_cpu_domain().is_err());
    let imported = crate::ingress::receive_page_from(
        &mut destination_node,
        address,
        serde_json::from_value(reply.value).unwrap(),
        block,
        settings.genesis(),
        now,
    )
    .unwrap();
    assert_eq!(imported, block);
    assert_eq!(destination_node.read_active().unwrap().0, block);
    let paid = destination_node
        .public_service_cpu_domain()
        .unwrap()
        .observe()
        .unwrap();
    assert!(!paid.accounting_unavailable);
    assert_eq!(paid.in_flight, 0);
    stop.store(true, Ordering::Release);
    let metrics = worker.join().unwrap().unwrap();
    assert_eq!(metrics.completed_read, 1);
    assert_eq!(metrics.pq_authentication_attempts, 3);
    assert_eq!(metrics.completed_submit, 0);
}

#[test]
fn pq_response_expiry_stop_and_cancel_do_not_start_signing() {
    let settings = Settings::development(Some(1)).unwrap();
    let owner = server();
    let cookie = owner
        .cookie(
            &settings,
            hello(&identity(72)),
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
    let intake = owner.listener_intake().unwrap();
    let before = intake.pq_authentication.usage().unwrap();
    let now = Instant::now();
    for (deadline, stopped, cancelled, expected) in [
        (now, false, false, "PUBLIC_REQUEST_DEADLINE"),
        (
            now + Duration::from_secs(10),
            true,
            false,
            "PUBLIC_REQUEST_DEADLINE",
        ),
        (
            now + Duration::from_secs(10),
            false,
            true,
            "PUBLIC_REQUEST_CANCELLED",
        ),
    ] {
        let stop = AtomicBool::new(stopped);
        let cancelled = AtomicBool::new(cancelled);
        // Both a native success and a bounded refusal use the same original
        // operation lifetime. Neither justifies a new response-signing budget.
        for outcome in [
            Ok(json!({"head":"fixture"})),
            Err("PUBLIC_MUTATION_CPU_BUDGET".into()),
        ] {
            let error = response(&owner, &settings, &cookie, outcome, &mut None, &|| {
                task_alive(deadline, &stop, &cancelled)
            })
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
        }
    }
    let after = intake.pq_authentication.usage().unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.bytes, before.bytes);
    assert_eq!(after.actual_thread_cpu_ns, before.actual_thread_cpu_ns);
    assert_eq!(after.unavailable, before.unavailable);
}

#[test]
fn pq_response_cancellation_between_encoding_and_signing_stops_new_work() {
    let settings = Settings::development(Some(1)).unwrap();
    let owner = server();
    let cookie = owner
        .cookie(
            &settings,
            hello(&identity(72)),
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
    let intake = owner.listener_intake().unwrap();
    let stop = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    // A cancellation arriving after entry must prevent a signature. If it
    // arrives after signature admission, the one in-progress signature is
    // charged, but the remaining response is abandoned without a new budget.
    for (cancel_after_check, expected_signatures) in [(1, 0), (2, 1), (3, 1)] {
        let cancelled = AtomicBool::new(false);
        let checks = Cell::new(0);
        let before = intake.pq_authentication.usage().unwrap();
        let mut signing = Some(owner.reserve_response_signing(&intake).unwrap());
        let error = response(
            &owner,
            &settings,
            &cookie,
            Ok(json!({"head":"fixture"})),
            &mut signing,
            &|| {
                task_alive(deadline, &stop, &cancelled)?;
                checks.set(checks.get() + 1);
                if checks.get() == cancel_after_check {
                    cancelled.store(true, Ordering::Release);
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
        drop(signing);
        let after = intake.pq_authentication.usage().unwrap();
        // The response attempt/bytes were promised before work, and remain
        // consumed even when cancellation prevents its actual signature.
        assert_eq!(after.attempts - before.attempts, 1);
        assert_eq!(
            after.known_intervals - before.known_intervals,
            expected_signatures
        );
        assert_eq!(
            after.unused_response_reservations - before.unused_response_reservations,
            u64::from(expected_signatures == 0)
        );
        assert!(!after.unavailable);
    }
}
