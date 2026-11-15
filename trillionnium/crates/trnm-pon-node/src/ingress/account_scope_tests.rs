//! Current account scope must be rechecked before network effects.
//! These internal Settings mutations model configuration mistakes, not a remote
//! ability to rewrite the Node's private settings or a production qualification.
use super::*;

fn identities() -> (AuthenticatedServer, AuthenticatedClient) {
    let server = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let caller = DevelopmentIdentity::from_secret_hex(&hex::encode([72; 32])).unwrap();
    (
        AuthenticatedServer::new(server.clone(), vec![caller.public_key().into()], 1).unwrap(),
        AuthenticatedClient::new(caller, server.public_key().into(), 1).unwrap(),
    )
}

fn invalid_settings(baseline: &Settings) -> Vec<(String, Settings, &'static str)> {
    let mut cases = Vec::new();
    for (field, wrong, mistyped) in [
        ("production_activation", json!(true), json!("false")),
        ("not_mainnet", json!(false), json!("true")),
        ("coin_atomic_unit", json!("market-value"), json!(false)),
    ] {
        for (label, value) in [
            ("wrong", Some(wrong)),
            ("mistyped", Some(mistyped)),
            ("null", Some(Value::Null)),
            ("missing", None),
        ] {
            let mut settings = baseline.clone();
            let params = settings.app.params.as_object_mut().unwrap();
            if let Some(value) = value {
                params.insert(field.into(), value);
            } else {
                params.remove(field);
            }
            cases.push((
                format!("{field}-{label}"),
                settings,
                "ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED",
            ));
        }
    }
    for field in [
        "native_pq_profile",
        "native_pq_descriptor",
        "native_pq_anchor",
    ] {
        for (label, value) in [("null", Value::Null), ("unknown", json!("unavailable"))] {
            let mut settings = baseline.clone();
            settings.app.params[field] = value;
            cases.push((
                format!("{field}-{label}"),
                settings,
                "PQ_ACCOUNT_PROFILE_UNAVAILABLE",
            ));
        }
    }
    cases
}

fn assert_same_identity(left: &Settings, right: &Settings) {
    assert_eq!(left.network(), right.network());
    assert_eq!(left.parameters(), right.parameters());
    assert_eq!(left.genesis(), right.genesis());
}

#[test]
fn invalid_account_scope_refuses_classical_session_and_signed_request() {
    let baseline = Settings::development(Some(1)).unwrap();
    let (server, client) = identities();
    for (label, settings, expected) in invalid_settings(&baseline) {
        assert_same_identity(&settings, &baseline);
        let error = authenticated_session(&settings, client.public_key(), server.public_key(), 1)
            .unwrap_err();
        assert_eq!(error.to_string(), expected, "session {label}");
        let error = authenticated_request_bytes(&settings, &client, 19, Request::Head).unwrap_err();
        assert_eq!(error.to_string(), expected, "signed request {label}");
    }
}

#[test]
fn current_local_scope_refuses_previously_valid_classical_request() {
    let baseline = Settings::development(Some(1)).unwrap();
    let (server, client) = identities();
    let wire = authenticated_request_bytes(&baseline, &client, 19, Request::Head).unwrap();
    let original = authenticate_request(&wire, &baseline, &server).unwrap();
    assert_eq!(original.frame.replay_nonce(), 19);
    assert_eq!(original.request, Request::Head);
    for (label, settings, expected) in invalid_settings(&baseline) {
        assert_same_identity(&settings, &baseline);
        let error = authenticate_request(&wire, &settings, &server).unwrap_err();
        assert_eq!(error.to_string(), expected, "{label}");
    }
    assert_eq!(
        authenticate_request(&wire, &baseline, &server)
            .unwrap()
            .wire,
        wire
    );
}

/// A real peer closes any attempted connection promptly. The receiver also
/// drains the accept queue after the caller returns, so an early caller error
/// cannot hide a connection that the observer thread has not yet scheduled.
fn observe_connections<T>(operation: impl FnOnce(SocketAddr) -> T) -> (T, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let receiver_stop = stop.clone();
    let receiver = thread::spawn(move || {
        let mut accepted = 0;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted += 1;
                    drop(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if receiver_stop.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("listener failed: {error}"),
            }
        }
        accepted
    });
    let result = operation(address);
    stop.store(true, Ordering::Release);
    (result, receiver.join().unwrap())
}

#[test]
fn invalid_account_scope_never_connects_or_advances_classical_clients() {
    let baseline = Settings::development(Some(1)).unwrap();
    let (server, client) = identities();
    for (label, settings, expected) in invalid_settings(&baseline) {
        for protected in [false, true] {
            let mut nonce = 19;
            let (result, connections) = observe_connections(|address| {
                if protected {
                    call_authenticated_protected(
                        address,
                        &Request::Head,
                        &settings,
                        &client,
                        &mut nonce,
                    )
                } else {
                    call_authenticated(address, &Request::Head, &settings, &client, &mut nonce)
                }
            });
            assert_eq!(
                connections, 0,
                "authenticated {label}, protected={protected}"
            );
            assert_eq!(nonce, 19, "{label}");
            assert_eq!(result.unwrap_err().to_string(), expected, "{label}");
        }
        let (result, connections) =
            observe_connections(|address| call_protected(address, &Request::Head, &settings));
        assert_eq!(connections, 0, "anonymous protected {label}");
        assert_eq!(result.unwrap_err().to_string(), expected, "{label}");

        let (result, connections) = observe_connections(|address| {
            public_v2::call_public_protected_v2(
                address,
                &Request::Head,
                &settings,
                server.public_key(),
                &client.identity,
                public_v2::PublicPolicy::development(),
            )
        });
        assert_eq!(connections, 0, "public V2 {label}");
        assert_eq!(result.unwrap_err().to_string(), expected, "{label}");

        let ((result, metrics), connections) = observe_connections(|address| {
            public_v3::call_public_protected_v3_with_metrics(
                address,
                &public_v3::Request::Head,
                &settings,
                server.public_key(),
                &client.identity,
                public_v3::PublicPolicy::development(),
            )
        });
        assert_eq!(connections, 0, "public V3 {label}");
        assert_eq!(result.unwrap_err().to_string(), expected, "{label}");
        assert_eq!(
            metrics.failed_stage,
            Some(public_v3::PublicClientStage::Construction)
        );
        assert_eq!(metrics.challenge_ns, 0);
        assert_eq!(metrics.solution_search_ns, 0);
        assert_eq!(metrics.solution_trials, 0);
        assert!(!metrics.solution_found);
        assert_eq!(metrics.solution_body_response_ns, 0);
    }
}

#[test]
fn valid_development_scope_retains_classical_signature_and_socket_path() {
    let settings = Settings::development(Some(1)).unwrap();
    let (server, client) = identities();
    let wire = authenticated_request_bytes(&settings, &client, 19, Request::Head).unwrap();
    let verified = authenticate_request(&wire, &settings, &server).unwrap();
    assert_eq!(verified.frame.replay_nonce(), 19);
    assert_eq!(verified.request, Request::Head);
    assert_eq!(verified.wire, wire);
    let mut nonce = 19;
    let (result, connections) = observe_connections(|address| {
        call_authenticated(address, &Request::Head, &settings, &client, &mut nonce)
    });
    assert_eq!(connections, 1);
    assert!(result.is_err()); // The observed peer intentionally closes its socket.
    assert_eq!(nonce, 19);
}

#[test]
fn explicit_pq_selector_retains_classical_route_refusal_precedence() {
    let baseline = Settings::development(Some(1)).unwrap();
    let (server, client) = identities();
    for selection in [Value::Null, json!("unavailable-pq-profile")] {
        let mut settings = baseline.clone();
        settings.app.params["account_authorization_profile"] = selection;
        settings.app.params["production_activation"] = json!(true);
        let error = authenticated_session(&settings, client.public_key(), server.public_key(), 1)
            .unwrap_err();
        assert_eq!(error.to_string(), "AUTH_CLASSICAL_FOR_PQ_PROFILE");
    }
}

fn pq_identity(seed_byte: u8) -> public_v3::PqPublicIdentity {
    use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    let seed = zeroize::Zeroizing::new([seed_byte; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    public_v3::PqPublicIdentity::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap())
        .unwrap()
}

fn invalid_pq_settings(baseline: &Settings) -> Vec<(String, Settings, &'static str)> {
    let mut cases = invalid_settings(baseline);
    for (label, selection) in [
        ("null", Value::Null),
        ("unknown", json!("unavailable-pq-profile")),
    ] {
        let mut settings = baseline.clone();
        settings.app.params["account_authorization_profile"] = selection;
        cases.push((
            format!("account-selector-{label}"),
            settings,
            "PQ_ACCOUNT_PROFILE_UNAVAILABLE",
        ));
    }
    cases
}

fn assert_pq_policy_refusal(
    label: &str,
    settings: &Settings,
    server: &public_v3::PqPublicIdentity,
    caller: &public_v3::PqPublicIdentity,
    expected: &str,
) {
    let plaintext = pq_network::PqNetworkPolicy::new(
        settings,
        server.public_spki(),
        1,
        [caller.public_spki().to_vec()],
    );
    let tls = pq_network::PqNetworkPolicy::new_tls13(
        settings,
        server.public_spki(),
        1,
        [caller.public_spki().to_vec()],
        pq_network::PqTlsPins::new([51; 32], "pq.example".into()).unwrap(),
    );
    for (transport, result) in [("plaintext", plaintext), ("TLS", tls)] {
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{transport} accepted damaged settings: {label}"));
        assert_eq!(error.to_string(), expected, "{transport} {label}");
    }
}

fn assert_pq_history_refusal(
    label: &str,
    settings: &Settings,
    server: &public_v3::PqPublicIdentity,
    caller: &public_v3::PqPublicIdentity,
    expected: &str,
) {
    for request in [
        public_v3::Request::Head,
        public_v3::Request::History {
            tip: hex::encode(settings.genesis()),
            after: hex::encode(settings.genesis()),
        },
    ] {
        let ((result, metrics), connections) = observe_connections(|address| {
            public_v3::call_public_history_pq_v4(
                address,
                &request,
                settings,
                server.public_spki(),
                digest(server.public_key()).unwrap(),
                caller,
                public_v3::PublicPolicy::development(),
                None,
            )
        });
        assert_eq!(connections, 0, "PQ History connected with {label}");
        assert_eq!(result.unwrap_err().to_string(), expected, "{label}");
        assert_eq!(
            metrics.failed_stage,
            Some(public_v3::PublicClientStage::Construction)
        );
        assert_eq!(metrics.challenge_ns, 0);
        assert_eq!(metrics.solution_search_ns, 0);
        assert_eq!(metrics.solution_trials, 0);
        assert!(!metrics.solution_found);
        assert_eq!(metrics.solution_body_response_ns, 0);
    }
}

#[test]
fn invalid_account_scope_refuses_pq_network_policy() {
    let baseline = Settings::development(Some(1)).unwrap();
    let server = pq_identity(71);
    let caller = pq_identity(72);
    for (label, settings, expected) in invalid_pq_settings(&baseline) {
        assert_same_identity(&settings, &baseline);
        assert_pq_policy_refusal(&label, &settings, &server, &caller, expected);
    }
}

#[test]
fn invalid_account_scope_never_connects_pq_history_client() {
    let baseline = Settings::development(Some(1)).unwrap();
    let server = pq_identity(71);
    let caller = pq_identity(72);
    for (label, settings, expected) in invalid_pq_settings(&baseline) {
        assert_same_identity(&settings, &baseline);
        assert_pq_history_refusal(&label, &settings, &server, &caller, expected);
    }
}

#[test]
fn changed_native_pq_configuration_refuses_network_entry() {
    use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{
        application_v6::ApplicationPolicy, GenesisAccount,
    };
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    let accounts: Vec<_> = [81u8, 82, 83]
        .into_iter()
        .map(|n| GenesisAccount {
            spki: pq_identity(n).public_spki().to_vec(),
            balance: 1_000_000,
        })
        .collect();
    let policy = ApplicationPolicy {
        evaluators: accounts
            .iter()
            .take(2)
            .map(|account| ml_dsa_65_key_id_from_spki(&account.spki).unwrap())
            .collect(),
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
    };
    let baseline = Settings::native_pq_application_v6(&accounts, 1, &policy).unwrap();
    let server = pq_identity(71);
    let caller = pq_identity(72);
    // The valid native owner remains usable. The mutations retain the old
    // Settings identity but must not reuse it to authorize network IO.
    pq_network::PqNetworkPolicy::new(
        &baseline,
        server.public_spki(),
        1,
        [caller.public_spki().to_vec()],
    )
    .unwrap();
    for field in [
        "native_pq_v2_anchor",
        "native_pq_v2_descriptor",
        "native_pq_accounts_profile",
    ] {
        let mut settings = baseline.clone();
        settings.app.params[field] = json!("changed");
        assert_same_identity(&settings, &baseline);
        assert_pq_policy_refusal(field, &settings, &server, &caller, "PQ2_CONFIG_CHANGED");
        assert_pq_history_refusal(field, &settings, &server, &caller, "PQ2_CONFIG_CHANGED");
    }
}

#[test]
fn valid_account_scope_retains_pq_policy_and_history_socket_path() {
    let settings = Settings::development(Some(1)).unwrap();
    let server = pq_identity(71);
    let caller = pq_identity(72);
    let plaintext = pq_network::PqNetworkPolicy::new(
        &settings,
        server.public_spki(),
        1,
        [caller.public_spki().to_vec()],
    )
    .unwrap();
    let tls = pq_network::PqNetworkPolicy::new_tls13(
        &settings,
        server.public_spki(),
        1,
        [caller.public_spki().to_vec()],
        pq_network::PqTlsPins::new([51; 32], "pq.example".into()).unwrap(),
    )
    .unwrap();
    assert!(!plaintext.transport_requires_tls());
    assert!(tls.transport_requires_tls());
    assert_ne!(plaintext.id(), tls.id());
    let ((result, metrics), connections) = observe_connections(|address| {
        public_v3::call_public_history_pq_v4(
            address,
            &public_v3::Request::Head,
            &settings,
            server.public_spki(),
            digest(server.public_key()).unwrap(),
            &caller,
            public_v3::PublicPolicy::development(),
            None,
        )
    });
    assert_eq!(connections, 1);
    assert!(result.is_err()); // The observed peer closes its accepted socket.
    assert_eq!(
        metrics.failed_stage,
        Some(public_v3::PublicClientStage::Challenge)
    );
}
