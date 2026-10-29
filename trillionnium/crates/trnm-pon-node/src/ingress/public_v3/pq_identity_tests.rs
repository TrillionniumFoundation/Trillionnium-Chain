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
    let bytes = response(&owner, &settings, &cookie, Ok(json!({"head":"fixture"}))).unwrap();
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
        .completion_identity_for_settings(&settings)
        .is_ok());
    assert!(completed
        .completion_identity_for_settings(&Settings::development(Some(1)).unwrap())
        .is_err());
    let block = node.admit(&packet, now).unwrap();
    node.activate(block).unwrap();
    let expected_packet = packet.encode_for_settings(&settings).unwrap();
    assert!(expected_packet.starts_with(b"PQP6"));
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
