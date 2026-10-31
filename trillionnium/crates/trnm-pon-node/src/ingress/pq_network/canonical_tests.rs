use super::*;
use crate::Packet;
use std::collections::BTreeSet;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{self as accounts, application_v6};
use trnm_protocol::pq_native_accounts_v2 as wire;
use zeroize::Zeroizing;

pub(crate) fn key(seed: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}
pub(crate) fn setup() -> (Settings, Arc<PqNetworkPolicy>) {
    let seeded: Vec<_> = [1, 2, 3]
        .into_iter()
        .map(|seed| accounts::GenesisAccount {
            spki: key(seed).public_spki().to_vec(),
            balance: 1_000_000_000,
        })
        .collect();
    let settings = Settings::native_pq_application_v6(
        &seeded,
        super::super::now().unwrap() - 100,
        &application_v6::ApplicationPolicy {
            evaluators: BTreeSet::from([key(2).public_key_id(), key(3).public_key_id()]),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        },
    )
    .unwrap();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            key(71).public_spki(),
            1,
            [key(72).public_spki().to_vec()],
        )
        .unwrap(),
    );
    (settings, policy)
}
pub(crate) fn transfer(settings: &Settings) -> Vec<u8> {
    let payload = [
        key(2).public_key_id().as_slice(),
        &42_u64.to_le_bytes(),
        &0_u16.to_be_bytes(),
    ]
    .concat();
    signed_command(settings, 1, 1, 1, &payload)
}
fn signed_command(settings: &Settings, seed: u8, nonce: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
    let signer = key(seed);
    let common = wire::Common {
        context: accounts::context(&settings.app).unwrap(),
        account: signer.public_key_id(),
        generation: 1,
        nonce,
        expires_at: settings.genesis_time() + 200,
        max_fee: 100_000,
    };
    let witness = wire::WitnessKey {
        role: 1,
        generation: 1,
        key_id: signer.public_key_id(),
        spki: None,
    };
    let core = wire::signing_core_for_profile(
        wire::AccountProfile::ApplicationV6,
        &common,
        kind,
        payload,
        std::slice::from_ref(&witness),
    )
    .unwrap();
    let statement = wire::signing_statement_for_profile(
        wire::AccountProfile::ApplicationV6,
        &common,
        kind,
        payload,
        std::slice::from_ref(&witness),
        0,
    )
    .unwrap();
    let frame = signer
        .sign_statement(
            &statement,
            &PqFrameExpectation {
                purpose: 1,
                network: common.context.network,
                owner_context: wire::owner_context_for_profile(
                    wire::AccountProfile::ApplicationV6,
                    &common,
                    kind,
                    1,
                )
                .unwrap(),
                signer_key_id: signer.public_key_id(),
                owner_generation: 1,
                operation_sequence: nonce,
                expires_at: common.expires_at,
                now: settings.genesis_time(),
                payload: &core,
            },
        )
        .unwrap();
    wire::encode_for_profile(
        wire::AccountProfile::ApplicationV6,
        &common,
        kind,
        payload,
        &[witness],
        &[frame.to_vec()],
    )
    .unwrap()
}

#[test]
fn pq6_payment_observer_replays_actual_settlement_and_refuses_reorg_and_wrong_bindings() {
    use trnm_protocol::pon_wire::hash;
    use trnm_service_settlement::native_budget::{NativeFundingSourceV1, NativePaymentQueryV1};
    let (settings, policy) = setup();
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap();
    let amount = 20_000_u64;
    let deadline = 20_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &key(1).public_key_id(),
            &1_u64.to_le_bytes(),
            &key(2).public_key_id(),
            &amount.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let reserve = signed_command(
        &settings,
        1,
        1,
        2,
        &[
            task.as_slice(),
            &key(2).public_key_id(),
            &amount.to_le_bytes(),
            &deadline.to_le_bytes(),
        ]
        .concat(),
    );
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![reserve],
            key(1).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let first = node.admit(&packet, super::super::now().unwrap()).unwrap();
    node.activate(first).unwrap();
    let output = [91; 32];
    let payload = [task.as_slice(), output.as_slice()].concat();
    let receipt = signed_command(&settings, 2, 1, 4, &payload);
    let settlement = signed_command(&settings, 1, 2, 5, &payload);
    let operation = wire::UnverifiedEnvelope::decode_for_profile(
        &settlement,
        wire::AccountProfile::ApplicationV6,
    )
    .unwrap()
    .wire_id();
    let query = NativePaymentQueryV1 {
        source: NativeFundingSourceV1::Task(task),
        subject: output,
        beneficiary: key(2).public_key_id(),
        operation,
        maximum_gross_units: amount,
    };
    assert!(node.native_payment_observation(&query).is_err());
    let packet = node
        .make_consensus_maintenance(
            first,
            vec![receipt, settlement],
            key(1).public_key_id(),
            settings.genesis_time() + 20,
            4096,
        )
        .unwrap();
    let settled = node.admit(&packet, super::super::now().unwrap()).unwrap();
    node.activate(settled).unwrap();
    let observed = node.native_payment_observation(&query).unwrap();
    assert_eq!(observed.anchor.block, settled);
    assert_eq!(observed.gross_escrow_debit, amount);
    assert_eq!(observed.beneficiary_credit, amount);
    for wrong in [
        NativePaymentQueryV1 {
            subject: [92; 32],
            ..query.clone()
        },
        NativePaymentQueryV1 {
            beneficiary: key(3).public_key_id(),
            ..query.clone()
        },
        NativePaymentQueryV1 {
            maximum_gross_units: amount - 1,
            ..query.clone()
        },
        NativePaymentQueryV1 {
            operation: [93; 32],
            ..query.clone()
        },
    ] {
        assert!(node.native_payment_observation(&wrong).is_err());
    }
    drop(node);
    let mut node = Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap();
    assert_eq!(node.native_payment_observation(&query).unwrap(), observed);
    // An ancestor locator cannot undo settled work. Only a genuinely heavier
    // PoN fork may remove the settlement from the active branch.
    assert_eq!(node.activate(first).unwrap(), settled);
    assert_eq!(node.native_payment_observation(&query).unwrap(), observed);
    let mut competing = first;
    for height in [2, 3] {
        let fork = node
            .make_consensus_maintenance(
                competing,
                Vec::new(),
                key(3).public_key_id(),
                settings.genesis_time() + height * 10,
                4096,
            )
            .unwrap();
        competing = node.admit(&fork, super::super::now().unwrap()).unwrap();
    }
    assert_eq!(node.activate(competing).unwrap(), competing);
    assert_eq!(node.packet(settled).unwrap().id().unwrap(), settled);
    assert!(node.native_payment_observation(&query).is_err());
    drop(node);
    let node = Node::open_with_pq_network(dir.path(), settings, 1, &policy).unwrap();
    assert_eq!(node.active().unwrap().0, competing);
    assert!(node.native_payment_observation(&query).is_err());
}

#[test]
fn pq6_packet_executes_through_actual_pnq2_socket_and_reopens() {
    let (settings, policy) = setup();
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make_consensus_maintenance(
            settings.genesis(),
            vec![transfer(&settings)],
            key(1).public_key_id(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let raw = packet.encode_for_settings(&settings).unwrap();
    assert!(raw.starts_with(b"PQP6\x06\0\0\0"));
    assert!(Packet::decode(&raw).is_err());
    let id = packet.id().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let server = PqServer::new(policy.clone(), key(71)).unwrap();
    let thread = std::thread::spawn(move || {
        serve_pq_authenticated(listener, node, Duration::from_secs(30), stopped, server).unwrap()
    });
    let client = PqClient::new(policy.clone(), key(72)).unwrap();
    let request = client
        .prepare(
            1,
            super::super::now().unwrap() + 60,
            Request::Submit {
                packet: hex::encode(raw),
            },
        )
        .unwrap();
    let response = client
        .send(address, &request, Duration::from_secs(10))
        .unwrap();
    assert!(response.ok, "{:?}", response.value);
    assert_eq!(response.value["block"], hex::encode(id));
    let replay = client
        .send(address, &request, Duration::from_secs(10))
        .unwrap();
    assert_eq!(response, replay);
    stop.store(true, Ordering::Release);
    let metrics = thread.join().unwrap();
    assert_eq!(metrics.accepted, 2);
    let reopened = Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap();
    assert_eq!(reopened.active().unwrap().0, id);
    let state = reopened.state_at(id).unwrap();
    assert_eq!(
        state[&format!("account:{}", hex::encode(key(2).public_key_id()))]["balance"],
        1_000_000_042_u64
    );
    let status = reopened.pq_network_status(&policy).unwrap();
    assert_eq!(status["ingress_connections"], 2);
    assert_eq!(status["inbound_signature_attempts"], 2);
    assert_eq!(status["records"], 1);
    assert_eq!(status["transport_confidentiality"], false);
    assert!(Node::open(dir.path(), settings, 1).is_err());
}

#[test]
fn failed_real_signatures_exhaust_durable_budget_without_charging_claimed_accounts() {
    let (settings, policy) = setup();
    let dir = tempfile::tempdir().unwrap();
    let node =
        Mutex::new(Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap());
    let initial = node.lock().unwrap().state_at(settings.genesis()).unwrap();
    let client = PqClient::new(policy.clone(), key(72)).unwrap();
    let valid = client
        .prepare(1, super::super::now().unwrap() + 60, Request::Head)
        .unwrap();
    let mut bad = valid.wire().to_vec();
    bad[8 + TPQ1_UNSIGNED_BYTES + 2] ^= 1;
    let server = PqServer::new(policy.clone(), key(71)).unwrap();
    for _ in 0..MAX_INBOUND_VERIFICATIONS {
        assert!(server
            .handle(&node, &bad, Instant::now() + Duration::from_secs(10))
            .is_err());
    }
    assert!(server
        .handle(
            &node,
            valid.wire(),
            Instant::now() + Duration::from_secs(10)
        )
        .unwrap_err()
        .to_string()
        .contains("PQ_NETWORK_INGRESS_BUDGET"));
    let owner = node.into_inner().unwrap();
    assert_eq!(owner.state_at(settings.genesis()).unwrap(), initial);
    let status = owner.pq_network_status(&policy).unwrap();
    assert_eq!(status["records"], 0);
    assert_eq!(
        status["inbound_signature_attempts"],
        MAX_INBOUND_VERIFICATIONS
    );
    drop(owner);
    let reopened =
        Mutex::new(Node::open_with_pq_network(dir.path(), settings, 1, &policy).unwrap());
    assert!(server
        .handle(
            &reopened,
            valid.wire(),
            Instant::now() + Duration::from_secs(10)
        )
        .unwrap_err()
        .to_string()
        .contains("PQ_NETWORK_INGRESS_BUDGET"));
    let mut old = valid.wire().to_vec();
    old[..4].copy_from_slice(b"PNQ1");
    assert!(policy
        .verify_request(&old, super::super::now().unwrap())
        .is_err());
    assert_eq!(
        reopened.lock().unwrap().pq_network_status(&policy).unwrap()["inbound_signature_attempts"],
        MAX_INBOUND_VERIFICATIONS
    );
}

#[test]
fn declared_oversize_is_rejected_before_body_allocation_and_survives_reopen() {
    use std::io::Write;
    let (settings, policy) = setup();
    let dir = tempfile::tempdir().unwrap();
    let node =
        Mutex::new(Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .write_all(&((MAX_WIRE + 1) as u32).to_be_bytes())
        .unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let server = PqServer::new(policy.clone(), key(71)).unwrap();
    assert!(server
        .read_request(&node, &mut stream, Instant::now() + Duration::from_secs(2))
        .is_err());
    drop(node);
    let owner = Node::open_with_pq_network(dir.path(), settings, 1, &policy).unwrap();
    let status = owner.pq_network_status(&policy).unwrap();
    assert_eq!(status["ingress_connections"], 1);
    assert_eq!(status["ingress_bytes"], 0);
    assert_eq!(status["inbound_signature_attempts"], 0);
}

#[test]
fn classic_authenticated_session_is_rejected_for_pq_only_settings() {
    let (pq_settings, _) = setup();
    let client =
        crate::ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([7; 32])).unwrap();
    let server =
        crate::ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([8; 32])).unwrap();
    let error = crate::ingress::authenticated_session(
        &pq_settings,
        client.public_key(),
        server.public_key(),
        1,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("AUTH_CLASSICAL_FOR_PQ_PROFILE"),
        "{error}"
    );

    // The negative gate must not disable the explicitly separate classical
    // development mode, whose existing Ed25519 authentication stays unchanged.
    let legacy = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
    assert!(crate::ingress::authenticated_session(
        &legacy,
        client.public_key(),
        server.public_key(),
        1,
    )
    .is_ok());
}
