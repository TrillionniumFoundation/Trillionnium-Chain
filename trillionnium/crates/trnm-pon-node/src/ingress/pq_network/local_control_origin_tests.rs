fn control_codes() -> [(crate::ErrorCode, &'static str); 3] {
    [
        (crate::ErrorCode::PqNetworkDeadline, "PQ_NETWORK_DEADLINE"),
        (crate::ErrorCode::PqNetworkExpired, "PQ_NETWORK_EXPIRED"),
        (crate::ErrorCode::PqNetworkRevoked, "PQ_NETWORK_REVOKED"),
    ]
}

// An intentionally dishonest, correctly pinned native PQ response peer. It
// supplies actual signed bytes to the original PqClient::send boundary. This
// is a remote-error injection control, not an alternate production listener.
fn quoted_peer_exchange(
    client: &PqClient,
    prepared: &PreparedPqRequest,
    response: Vec<u8>,
) -> (Result<PqResponse>, Value) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let expected_request = prepared.wire().to_vec();
    let policy = client.policy.clone();
    let served_wire = response.clone();
    let end = Instant::now() + Duration::from_secs(2);
    let worker = thread::spawn(move || -> Result<()> {
        loop {
            ensure(Instant::now() < end, "TEST_PQ_QUOTED_PEER_DEADLINE")?;
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let received = crate::ingress::read_frame_deadline(&mut stream, end)?;
                    ensure(received == expected_request, "TEST_PQ_QUOTED_REQUEST_BYTES")?;
                    policy.verify_request(&received, crate::ingress::now()?)?;
                    return crate::ingress::write_frame_deadline(&mut stream, &response, end);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        }
    });
    let started = Instant::now();
    let result = client.send(address, prepared, Duration::from_secs(2));
    let elapsed_ns = started.elapsed().as_nanos();
    let joined = match worker.join() {
        Ok(Ok(())) => json!({"joined":true,"served":true}),
        Ok(Err(error)) => json!({"joined":true,"served":false,"error":error.to_string()}),
        Err(_) => json!({"joined":true,"served":false,"panicked":true}),
    };
    let outcome = match &result {
        Ok(reply) => json!({"verified_response":reply}),
        Err(error) => json!({"error":error.to_string(),"kind":format!("{:?}",error.kind())}),
    };
    let observation = json!({"request_wire_hex":hex::encode(prepared.wire()),
        "served_response_wire_hex":hex::encode(served_wire),"elapsed_ns":elapsed_ns,
        "original_test_client_budget_seconds":2,"server":joined,"outcome":outcome});
    (result, observation)
}

#[test]
fn actual_mldsa_remote_control_text_and_forgery_never_authorize_local_cancellation() {
    let settings = settings();
    let policy = policy(&settings, 1);
    let client = PqClient::new(policy.clone(), signer(72)).unwrap();
    let server = PqServer::new(policy, signer(71)).unwrap();
    let expiry = crate::ingress::now().unwrap() + 60;
    let mut observations = Vec::new();
    let mut checks = Vec::new();
    for (sequence, (code, wire)) in (1..=3).zip(control_codes()) {
        let request = client.prepare(sequence, expiry, Request::Head).unwrap();
        let signed = server
            .response(&request.verified, Err(Error::remote(wire)))
            .unwrap();
        let (valid, observation) = quoted_peer_exchange(&client, &request, signed.clone());
        let quoted = valid
            .as_ref()
            .ok()
            .and_then(|reply| reply.value.get("error"))
            .and_then(Value::as_str);
        checks.push((
            format!("{wire}:real_signed_refusal_returns_data"),
            valid.as_ref().is_ok_and(|reply| !reply.ok)
                && quoted == Some(wire)
                && observation["server"]["served"] == true,
        ));
        checks.push((
            format!("{wire}:received_text_cannot_parse_to_local_code"),
            quoted.is_some_and(|text| {
                let parsed = Error::from(text);
                parsed.kind() == crate::ErrorKind::Unclassified
                    && parsed.code().is_none()
                    && !parsed.is(code)
                    && !parsed.requires_owner_stop()
            }),
        ));
        checks.push((
            format!("{wire}:received_refusal_wrapper_stays_remote"),
            quoted.is_some_and(|text| {
                let remote = Error::remote(text);
                remote.kind() == crate::ErrorKind::RemoteRefusal && remote.code().is_none()
            }),
        ));
        observations.push(json!({"diagnostic":wire,"case":"actual-native-signed-refusal","observation":observation}));
        let mut forged = signed;
        forged[8 + TPQ1_UNSIGNED_BYTES] ^= 1;
        let (invalid, observation) = quoted_peer_exchange(&client, &request, forged);
        checks.push((
            format!("{wire}:forged_signature_is_rejected_before_quoted_error"),
            invalid.as_ref().is_err_and(|error| {
                error.to_string().starts_with("PQ_NETWORK_CRYPTO:")
                    && error.kind() != crate::ErrorKind::Cancelled
                    && !error.is(code)
            }) && observation["server"]["served"] == true,
        ));
        observations.push(json!({"diagnostic":wire,"case":"actual-signature-corruption","observation":observation}));
    }
    let failures: Vec<_> = checks
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| name.as_str())
        .collect();
    println!(
        "{}",
        json!({"schema":"pq-real-signed-remote-control-origin-v1","planned_calls":6,
        "observed_calls":observations.len(),"observations":observations,"checks":checks,"failures":failures,
        "scope":"real native ML-DSA, real PqClient TCP and signed response verification; explicitly dishonest signed-response peer",
        "injected_local_cancellation":false,"whole_chain_pq":false})
    );
    assert!(
        failures.is_empty(),
        "PQ remote origin controls failed: {failures:?}"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    ExplicitLocal,
    QuotedText,
    RemoteRefusal,
    RemoteTerminal,
    RemoteRetryable,
}

impl Origin {
    fn error(self, code: crate::ErrorCode, wire: &str) -> Error {
        match self {
            Self::ExplicitLocal => Error::new(code),
            Self::QuotedText => Error::from(wire),
            Self::RemoteRefusal => Error::remote(wire),
            Self::RemoteTerminal => Error::authenticated_remote(true, wire),
            Self::RemoteRetryable => Error::authenticated_remote(false, wire),
        }
    }
}

#[test]
fn actual_durable_intent_cleanup_requires_local_origin_for_each_pq_control_code() {
    let settings = settings();
    let policy = policy(&settings, 1);
    let base = settings.genesis_time();
    let setup_directory = tempfile::tempdir().unwrap();
    let mut setup =
        Node::open_with_pq_network(setup_directory.path(), settings.clone(), 1, &policy).unwrap();
    let left = setup
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            base + 10,
            4096,
        )
        .unwrap();
    let left_id = setup.admit(&left, crate::ingress::now().unwrap()).unwrap();
    setup
        .activate_observed(left_id, crate::ingress::now().unwrap())
        .unwrap();
    let right = setup
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(1).unwrap(),
            base + 11,
            4096,
        )
        .unwrap();
    let right_id = setup.admit(&right, crate::ingress::now().unwrap()).unwrap();
    let target = setup
        .make(
            right_id,
            vec![],
            crate::development_public(1).unwrap(),
            base + 21,
            4096,
        )
        .unwrap();
    let packets = [left, right, target];
    for packet in &packets {
        WorkCheckedPacket::verify(packet.clone()).unwrap();
    }
    let packet_bytes: Vec<_> = packets
        .iter()
        .map(|packet| hex::encode(packet.encode().unwrap()))
        .collect();
    println!(
        "{}",
        json!({"schema":"pq-intent-origin-plan-v1","planned_cases":15,
        "original_complete_packets_hex":packet_bytes,
        "source_of_cut":"existing fault hook after genuine durable intent",
        "injected_error_origin":true,"actual_elapsed_deadline_or_revocation_claimed":false})
    );
    drop(setup);
    let mut observations = Vec::new();
    let mut checks = Vec::new();
    for (code, wire) in control_codes() {
        for origin in [
            Origin::ExplicitLocal,
            Origin::QuotedText,
            Origin::RemoteRefusal,
            Origin::RemoteTerminal,
            Origin::RemoteRetryable,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut node =
                Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
            let left = node
                .admit(&packets[0], crate::ingress::now().unwrap())
                .unwrap();
            node.activate_observed(left, crate::ingress::now().unwrap())
                .unwrap();
            node.admit(&packets[1], crate::ingress::now().unwrap())
                .unwrap();
            let target = node
                .admit(&packets[2], crate::ingress::now().unwrap())
                .unwrap();
            let before = capture(directory.path());
            let injected = origin.error(code, wire);
            let expected_kind = injected.kind();
            let expected_code = injected.code();
            let expected_message = injected.to_string();
            let mut injected = Some(injected);
            let mut actual_intent_visits = 0;
            let outcome = node.activate_with_fault(
                target,
                Some(&mut |point| {
                    if point == "intent" {
                        actual_intent_visits += 1;
                        Err(injected.take().expect("single original intent fault"))
                    } else {
                        Ok(())
                    }
                }),
            );
            let after = capture(directory.path());
            let local = origin == Origin::ExplicitLocal;
            let expected_done = if local { 2 } else { 0 };
            let expected_reason = if local { wire } else { "" };
            let expected_kind_is_preserved = outcome.as_ref().is_err_and(|error| {
                error.kind() == expected_kind
                    && error.code() == expected_code
                    && error.to_string() == expected_message
            });
            let lifecycle = after["lifecycle"].as_array().and_then(|rows| rows.last());
            let case_checks = [
                (
                    "known_snapshots",
                    before.get("capture_error").is_none() && after.get("capture_error").is_none(),
                ),
                ("actual_original_intent_once", actual_intent_visits == 1),
                (
                    "original_error_identity_preserved",
                    expected_kind_is_preserved,
                ),
                (
                    "only_explicit_local_origin_cancels_unpublished_intent",
                    after["reorg"][1] == hex::encode(target) && after["reorg"][4] == expected_done,
                ),
                (
                    "only_local_origin_obtains_cancellation_lifecycle",
                    lifecycle
                        .is_some_and(|row| row[1] == expected_done && row[3] == expected_reason),
                ),
                (
                    "state_and_peer_ledger_unchanged",
                    before["active"] == after["active"]
                        && before["peers"] == after["peers"]
                        && before["requests"] == after["requests"]
                        && before["metadata"] == after["metadata"],
                ),
                (
                    "original_owner_lock_stays_held",
                    before["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"] == true
                        && after["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"]
                            == true,
                ),
            ];
            let outcome = match outcome {
                Ok(id) => json!({"unexpected_success":hex::encode(id)}),
                Err(error) => {
                    json!({"error":error.to_string(),"kind":format!("{:?}",error.kind()),"code":format!("{:?}",error.code())})
                }
            };
            for (name, passed) in case_checks {
                checks.push((format!("{wire}/{origin:?}/{name}"), passed));
            }
            let mut checks_not_evaluated = Vec::new();
            if cfg!(unix) {
                checks.push((
                    format!("{wire}/{origin:?}/original_inode_device_identity"),
                    after["owner_fence"]["identity"]["supported"] == true
                        && after["owner_fence"]["identity"] == before["owner_fence"]["identity"],
                ));
            } else {
                checks_not_evaluated.push("original_inode_device_identity");
            }
            observations.push(json!({"diagnostic":wire,"origin":format!("{origin:?}"),"intent_visits":actual_intent_visits,
                "before":before,"after":after,"outcome":outcome,"unix_inode_device_probe_supported":cfg!(unix),
                "checks_not_evaluated":checks_not_evaluated}));
        }
    }
    let failures: Vec<_> = checks
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| name.as_str())
        .collect();
    println!(
        "{}",
        json!({"schema":"pq-intent-origin-observation-v1","planned_cases":15,"observed_cases":observations.len(),
        "observations":observations,"checks":checks,"failures":failures,
        "scope":"real complete W1 and M06 blocks, real durable intent, existing explicit error fault hook; classification boundary only",
        "actual_post_intent_durable_revocation":false,"physical_kill_cut":false,"public_paid_host_qualified":false,"whole_chain_pq":false})
    );
    assert!(
        failures.is_empty(),
        "PQ durable intent origin checks failed: {failures:?}"
    );
}
