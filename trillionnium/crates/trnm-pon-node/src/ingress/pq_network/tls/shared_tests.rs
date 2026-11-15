use super::*;
use crate::ingress::pq_network::{serve_pq_authenticated_shared, serve_pq_tls13_shared};
use crate::ingress::public_v3::{
    serve_public_protected_v3, PqPublicIdentity, PublicPolicy, PublicServer,
    Request as HistoryRequest,
};
use crate::public_submit::pq::{PinnedPqRecoveryClient, PqRecoveryTransport};
use std::collections::BTreeSet;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
    application_v6::ApplicationPolicy, GenesisAccount,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use trnm_protocol::pq_native_accounts_v2::{self as account_wire, AccountProfile};

fn paired_owner(encrypted: bool) {
    let fixture = Fixture::new();
    let now = crate::ingress::now().unwrap();
    let account_keys: Vec<_> = [81, 82, 83].into_iter().map(fixtures::key).collect();
    let accounts: Vec<_> = account_keys
        .iter()
        .map(|key| GenesisAccount {
            spki: key.public_key_to_der().unwrap(),
            balance: 1_000_000,
        })
        .collect();
    let ids: Vec<_> = accounts
        .iter()
        .map(|account| ml_dsa_65_key_id_from_spki(&account.spki).unwrap())
        .collect();
    let application = ApplicationPolicy {
        evaluators: ids.iter().take(2).copied().collect::<BTreeSet<_>>(),
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
    };
    let settings = Settings::native_pq_application_v6(&accounts, now - 100, &application).unwrap();
    let server_spki = fixture.server.key.public_key_to_der().unwrap();
    let peer_spki = fixture.peer.key.public_key_to_der().unwrap();
    let policy = Arc::new(if encrypted {
        PqNetworkPolicy::new_tls13(
            &settings,
            &server_spki,
            1,
            [peer_spki],
            fixture.policy.tls_pins().unwrap().clone(),
        )
        .unwrap()
    } else {
        PqNetworkPolicy::new(&settings, &server_spki, 1, [peer_spki]).unwrap()
    });
    let producer_dir = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let mut producer =
        Node::open_with_pq_network(producer_dir.path(), settings.clone(), 1, &policy).unwrap();
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(server_dir.path(), settings.clone(), 1, &policy).unwrap(),
    ));
    let common = account_wire::Common {
        context: account_wire::ChainContext {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        },
        account: ids[0],
        nonce: 1,
        expires_at: now + 300,
        max_fee: 100_000,
        generation: 1,
    };
    let witnesses = [account_wire::WitnessKey {
        role: 1,
        generation: 1,
        key_id: ids[0],
        spki: None,
    }];
    let mut payload = ids[1].to_vec();
    payload.extend(7_u64.to_le_bytes());
    payload.extend(0_u16.to_be_bytes());
    let statement = account_wire::signing_statement_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        1,
        &payload,
        &witnesses,
        0,
    )
    .unwrap();
    let signer = PqNativeSigningKey::from_owned_key(account_keys[0].clone(), ids[0]).unwrap();
    let signature = signer.sign_exact_message(&statement).unwrap();
    let mut frame = statement.to_vec();
    frame.extend((signature.len() as u16).to_be_bytes());
    frame.extend(signature);
    let transaction = account_wire::encode_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        1,
        &payload,
        &witnesses,
        &[frame],
    )
    .unwrap();
    let packet = producer
        .make_consensus_maintenance(
            settings.genesis(),
            vec![transaction],
            ids[0],
            now - 50,
            4096,
        )
        .unwrap();
    let id = producer.admit(&packet, now).unwrap();
    producer.activate(id).unwrap();
    let encoded = packet.encode_for_settings(&settings).unwrap();
    assert!(encoded.starts_with(b"PQP6"));
    assert!(crate::Packet::decode(&encoded).is_err());
    let native_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let native_address = native_listener.local_addr().unwrap();
    let history_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let history_address = history_listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let history_policy = PublicPolicy::development();
    let history_identity = PqPublicIdentity::from_signing_key(fixture.peer.signer());
    let history_server = PublicServer::new_pq_history(
        PqPublicIdentity::from_signing_key(fixture.server.signer()),
        history_policy,
    )
    .unwrap();
    let plain_client = PqClient::new(policy.clone(), fixture.peer.signer()).unwrap();
    let tls_client = if encrypted {
        Some(
            PqTlsClient::new(
                policy.clone(),
                fixture.peer.signer(),
                fixture.peer.tls(&fixture.ca),
            )
            .unwrap(),
        )
    } else {
        None
    };
    let transport = match tls_client.as_ref() {
        Some(client) => PqRecoveryTransport::HybridTlsLoopback(client),
        None => PqRecoveryTransport::AuthenticatedLoopback(&plain_client),
    };
    let client = PinnedPqRecoveryClient::new(
        &producer,
        transport,
        native_address,
        history_address,
        &history_identity,
        history_policy,
    )
    .unwrap();
    let native_owner = owner.clone();
    let native_stop = stop.clone();
    let native_thread = if encrypted {
        let server = PqTlsServer::new(
            policy.clone(),
            fixture.server.signer(),
            fixture.server.tls(&fixture.ca),
        )
        .unwrap();
        thread::spawn(move || {
            serve_pq_tls13_shared(
                native_listener,
                native_owner,
                Duration::from_secs(30),
                native_stop,
                server,
            )
        })
    } else {
        let server = PqServer::new(policy.clone(), fixture.server.signer()).unwrap();
        thread::spawn(move || {
            serve_pq_authenticated_shared(
                native_listener,
                native_owner,
                Duration::from_secs(30),
                native_stop,
                server,
            )
        })
    };
    let history_owner = owner.clone();
    let history_stop = stop.clone();
    let history_thread = thread::spawn(move || {
        serve_public_protected_v3(
            history_listener,
            history_owner,
            Duration::from_secs(30),
            history_stop,
            history_server,
        )
    });
    // Use a separate real local producer. Holding the shared remote mutex
    // across network IO would deadlock both actual services.
    let observed = (|| -> Result<_> {
        client.validate_for_node(&producer)?;
        // Complete the actual paid owner startup before the native mutation.
        let (ready, ready_metrics) = client.read_history(
            &producer,
            &HistoryRequest::Head,
            Instant::now() + Duration::from_secs(5),
        );
        let ready = ready?;
        assert!(ready.ok && ready_metrics.solution_found);
        assert_eq!(ready.value["tip"], hex::encode(settings.genesis()));
        let request = client.prepare(
            1,
            crate::ingress::now()? + 60,
            Request::Submit {
                packet: hex::encode(&encoded),
            },
        )?;
        client.validate_for_node(&producer)?;
        let acknowledgement =
            client.send_until(&request, Instant::now() + Duration::from_secs(5))?;
        let (head, head_metrics) = client.read_history(
            &producer,
            &HistoryRequest::Head,
            Instant::now() + Duration::from_secs(5),
        );
        let head = head?;
        let (history, history_metrics) = client.read_history(
            &producer,
            &HistoryRequest::History {
                tip: hex::encode(id),
                after: hex::encode(settings.genesis()),
            },
            Instant::now() + Duration::from_secs(5),
        );
        Ok((
            acknowledgement,
            head,
            head_metrics,
            history?,
            history_metrics,
        ))
    })();
    stop.store(true, Ordering::Release);
    let native_metrics = native_thread.join().unwrap().unwrap();
    let history_metrics = history_thread.join().unwrap().unwrap();
    let (acknowledgement, head, head_call, history, history_call) = observed.unwrap();
    assert!(acknowledgement.response().ok);
    assert_eq!(acknowledgement.response().value["block"], hex::encode(id));
    assert_eq!(acknowledgement.response().value["active"], hex::encode(id));
    assert!(head.ok && history.ok);
    assert_eq!(head.value["tip"], hex::encode(id));
    assert_eq!(head.value["height"], 1);
    assert!(head_call.solution_found && history_call.solution_found);
    assert_eq!(history.value["schema"], "pon-native-pq-history-v6");
    assert_eq!(
        history.value["packets"],
        serde_json::json!([hex::encode(&encoded)])
    );
    assert_eq!(owner.lock().unwrap().active().unwrap().0, id);
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&policy).unwrap()["records"],
        1
    );
    assert_eq!((native_metrics.accepted, native_metrics.refused), (1, 0));
    assert_eq!(history_metrics.completed_read, 3);
    assert_eq!(history_metrics.completed_submit, 0);
    assert_eq!(history_metrics.pq_authentication_attempts, 9);
    assert_eq!(client.history_transport(), "pq-signed-plaintext-loopback");
}

#[test]
fn shared_plain_native_npq6_submit_is_observed_by_actual_paid_pq_history() {
    paired_owner(false);
}

#[test]
fn shared_hybrid_tls_native_npq6_submit_is_observed_by_actual_paid_pq_history() {
    paired_owner(true);
}

#[test]
fn shared_native_listener_preserves_owner_transport_and_loopback_refusals() {
    let fixture = Fixture::new();
    let plain = Arc::new(
        PqNetworkPolicy::new(
            &fixture.settings,
            fixture.server.signer().public_spki(),
            1,
            [fixture.peer.signer().public_spki().to_vec()],
        )
        .unwrap(),
    );
    let stopped = Arc::new(AtomicBool::new(true));
    let directory = tempfile::tempdir().unwrap();
    let classical = Arc::new(Mutex::new(
        Node::open(directory.path(), fixture.settings.clone(), 1).unwrap(),
    ));
    assert!(serve_pq_authenticated_shared(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        classical,
        Duration::from_secs(1),
        stopped.clone(),
        PqServer::new(plain.clone(), fixture.server.signer()).unwrap(),
    )
    .is_err());
    let directory = tempfile::tempdir().unwrap();
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(directory.path(), fixture.settings.clone(), 1, &plain).unwrap(),
    ));
    let Err(error) = serve_pq_authenticated_shared(
        TcpListener::bind("0.0.0.0:0").unwrap(),
        owner.clone(),
        Duration::from_secs(1),
        stopped.clone(),
        PqServer::new(plain.clone(), fixture.server.signer()).unwrap(),
    ) else {
        panic!("non-loopback shared listener must refuse");
    };
    assert_eq!(error.to_string(), "PQ_NETWORK_LOOPBACK_ONLY");
    assert!(serve_pq_authenticated_shared(
        TcpListener::bind("127.0.0.1:0").unwrap(),
        owner.clone(),
        Duration::from_secs(1),
        stopped,
        PqServer::new(fixture.policy.clone(), fixture.server.signer()).unwrap(),
    )
    .is_err());
    assert_eq!(
        owner.lock().unwrap().pq_network_status(&plain).unwrap()["records"],
        0
    );
}

#[test]
fn shared_native_startup_lock_consumes_the_original_listener_lifetime() {
    let fixture = Fixture::new();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &fixture.settings,
            fixture.server.signer().public_spki(),
            1,
            [fixture.peer.signer().public_spki().to_vec()],
        )
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let owner = Arc::new(Mutex::new(
        Node::open_with_pq_network(directory.path(), fixture.settings.clone(), 1, &policy).unwrap(),
    ));
    let guard = owner.lock().unwrap();
    let worker_owner = owner.clone();
    let server = PqServer::new(policy, fixture.server.signer()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let result = serve_pq_authenticated_shared(
            listener,
            worker_owner,
            Duration::from_millis(50),
            Arc::new(AtomicBool::new(false)),
            server,
        );
        send.send(result).unwrap();
    });
    let observed = receive.recv_timeout(Duration::from_secs(2));
    drop(guard);
    worker.join().unwrap();
    let Err(error) = observed.unwrap() else {
        panic!("held owner must exhaust startup");
    };
    assert_eq!(error.to_string(), "PQ_NETWORK_DEADLINE");
}

#[test]
fn absolute_native_deadline_and_original_ten_second_cap_refuse_before_tcp() {
    let fixture = Fixture::new();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &fixture.settings,
            fixture.server.signer().public_spki(),
            1,
            [fixture.peer.signer().public_spki().to_vec()],
        )
        .unwrap(),
    );
    let plain = PqClient::new(policy, fixture.peer.signer()).unwrap();
    let tls = fixture.client();
    let expiry = crate::ingress::now().unwrap() + 60;
    let plain_request = plain.prepare(1, expiry, Request::Head).unwrap();
    let tls_request = tls.prepare(1, expiry, Request::Head).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let elapsed = Instant::now() - Duration::from_millis(1);
    for error in [
        plain
            .send_with_evidence_until(address, &plain_request, elapsed)
            .err()
            .unwrap(),
        tls.send_with_evidence_until(address, &tls_request, elapsed)
            .err()
            .unwrap(),
    ] {
        assert_eq!(error.to_string(), "PQ_NETWORK_DEADLINE");
    }
    let excessive = Instant::now() + Duration::from_secs(20);
    for error in [
        plain
            .send_with_evidence_until(address, &plain_request, excessive)
            .err()
            .unwrap(),
        tls.send_with_evidence_until(address, &tls_request, excessive)
            .err()
            .unwrap(),
    ] {
        assert_eq!(error.to_string(), "PQ_NETWORK_CLIENT_BUDGET");
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn absolute_native_expiry_is_local_typed_and_refuses_both_transports_before_tcp() {
    let fixture = Fixture::new();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &fixture.settings,
            fixture.server.signer().public_spki(),
            1,
            [fixture.peer.signer().public_spki().to_vec()],
        )
        .unwrap(),
    );
    let plain = PqClient::new(policy, fixture.peer.signer()).unwrap();
    let tls = fixture.client();
    let expiry = crate::ingress::now().unwrap() + 2;
    let plain_request = plain.prepare(1, expiry, Request::Head).unwrap();
    let tls_request = tls.prepare(1, expiry, Request::Head).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    thread::sleep(Duration::from_secs(3));
    for error in [
        plain
            .send_with_evidence_until(
                address,
                &plain_request,
                Instant::now() + Duration::from_secs(5),
            )
            .err()
            .unwrap(),
        tls.send_with_evidence_until(
            address,
            &tls_request,
            Instant::now() + Duration::from_secs(5),
        )
        .err()
        .unwrap(),
    ] {
        assert!(error.is(crate::ErrorCode::PqNetworkExpired));
        assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[path = "shared_tests/recovery_cases.rs"]
mod recovery_cases;
