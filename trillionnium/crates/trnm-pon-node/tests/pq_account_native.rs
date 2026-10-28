#![cfg(feature = "pq-native-openssl")]
//! The same PQG1/QTX1 fixture crosses the actual native Node store and W1 owner.
#[path = "../../trnm-mvcc-fee/tests/pq_account_owner.rs"]
mod account_cases;

use openssl::pkey::{KeyType, PKey};
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_mvcc_fee::pon_executor::pq_accounts;
use trnm_pon_node::{
    ingress::{
        self,
        pq_network::{PqClient, PqNetworkPolicy, PqServer},
    },
    Node, Packet, Settings,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

fn signer(seed: u8) -> PqNativeSigningKey {
    let key = PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[seed; 32]).unwrap();
    let id = ml_dsa_65_key_id_from_spki(&key.public_key_to_der().unwrap()).unwrap();
    PqNativeSigningKey::from_owned_key(key, id).unwrap()
}
fn context(f: &account_cases::Fixture) -> (Settings, Arc<PqNetworkPolicy>) {
    let settings = Settings::from_pq_account_import(
        pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).unwrap(),
    )
    .unwrap();
    let policy = Arc::new(
        PqNetworkPolicy::new(
            &settings,
            signer(111).public_spki(),
            1,
            [signer(112).public_spki().to_vec()],
        )
        .unwrap(),
    );
    (settings, policy)
}

#[test]
fn real_node_pq_account_packets_work_forks_reorg_and_cold_replay() {
    let f = account_cases::fixture();
    let (settings, policy) = context(&f);
    let dir = tempfile::tempdir().unwrap();
    assert!(
        Node::open(dir.path(), settings.clone(), 1).is_err(),
        "PQ accounts require the PQ network owner; no legacy constructor escape"
    );
    let mut node = Node::open_with_pq_network(dir.path(), settings.clone(), 4, &policy).unwrap();
    let genesis = settings.genesis();
    let time = settings.genesis_time();
    let a = node
        .make(
            genesis,
            vec![account_cases::signed(
                &f,
                &account_cases::transfer(&f, 0, 23, 1000),
                0,
            )],
            f.active[0],
            time + 10,
            4096,
        )
        .unwrap();
    let b = node
        .make(
            genesis,
            vec![account_cases::signed(
                &f,
                &account_cases::transfer(&f, 0, 23, 2000),
                0,
            )],
            f.active[0],
            time + 11,
            4096,
        )
        .unwrap();
    assert_eq!(
        Packet::decode(&a.encode().unwrap())
            .unwrap()
            .encode()
            .unwrap(),
        a.encode().unwrap()
    );
    let aid = node.admit(&a, time + 100).unwrap();
    let bid = node.admit(&b, time + 100).unwrap();
    node.activate(aid).unwrap();
    let exact_wire_id = trnm_protocol::pon_wire::hash(b"tx-id", &[&a.transactions[0]]);
    assert!(
        !node
            .confirmation(exact_wire_id, aid, time + 100)
            .unwrap()
            .reorged
    );
    let prior = node.active().unwrap().0;
    let other = if prior == aid { bid } else { aid };
    let child = node
        .make(
            other,
            vec![account_cases::signed(
                &f,
                &account_cases::transfer(&f, 1, 91, 3000),
                1,
            )],
            f.active[1],
            time + 20,
            4096,
        )
        .unwrap();
    let selected = node.admit(&child, time + 100).unwrap();
    node.activate_observed(selected, time + 100).unwrap();
    assert_eq!(node.active().unwrap().0, selected);
    assert_ne!(prior, other);
    let reorged = node.confirmation(exact_wire_id, aid, time + 100).unwrap();
    assert!(reorged.reorged);
    assert!(!reorged.confirmed && !reorged.finalized);
    let state = node.state_at(selected).unwrap();
    assert_eq!(
        state[&format!("account:{}", hex::encode(f.active[0]))]["nonce"],
        23
    );
    assert_eq!(
        state[&format!("account:{}", hex::encode(f.active[1]))]["nonce"],
        91
    );
    assert_eq!(
        state
            .iter()
            .filter(|(k, _)| k.starts_with("pq-import-liability:"))
            .count(),
        4
    );
    assert!(node
        .make(
            selected,
            vec![account_cases::signed(
                &f,
                &account_cases::transfer(&f, 1, 91, 1),
                1
            )],
            f.active[1],
            time + 30,
            4096
        )
        .is_err());
    // A PoN miner names a reward address; it need not belong to the import
    // roster. This does not install an account signing key or a spending right.
    let unknown = trnm_pon_node::development_public(0).unwrap();
    assert!(node.make(genesis, vec![], unknown, time + 10, 4096).is_ok());
    let mut forged = account_cases::transfer(&f, 0, 1, 1);
    forged.sender = unknown;
    assert!(node
        .make(
            genesis,
            vec![account_cases::signed(&f, &forged, 0)],
            unknown,
            time + 10,
            4096
        )
        .is_err());
    assert_eq!(
        node.pq_network_status(&policy).unwrap()["imported_transfer_accounts"],
        true
    );
    assert_eq!(
        node.pq_network_status(&policy).unwrap()["account_migration"],
        false
    );
    drop(node);
    let reopened = Node::open_with_pq_network(dir.path(), settings, 4, &policy).unwrap();
    assert_eq!(reopened.active().unwrap().0, selected);
    assert_eq!(reopened.state_at(selected).unwrap(), state);
}

#[test]
fn real_pq_transport_dispatch_consumes_qtx1_through_w1_and_native_account_owner() {
    let f = account_cases::fixture();
    let (settings, policy) = context(&f);
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open_with_pq_network(dir.path(), settings.clone(), 1, &policy).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![account_cases::signed(
                &f,
                &account_cases::transfer(&f, 0, 23, 1000),
                0,
            )],
            f.active[0],
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let id = packet.id().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = PqServer::new(policy.clone(), signer(111)).unwrap();
    let server_stop = stop.clone();
    let running = thread::spawn(move || {
        ingress::pq_network::serve_pq_authenticated(
            listener,
            node,
            Duration::from_secs(30),
            server_stop,
            server,
        )
        .unwrap()
    });
    let client = PqClient::new(policy.clone(), signer(112)).unwrap();
    let request = client
        .prepare(
            1,
            ingress::now().unwrap() + 60,
            ingress::Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let reply = client
        .send(address, &request, Duration::from_secs(5))
        .unwrap();
    assert!(reply.ok, "native PQ dispatch refused: {}", reply.value);
    assert_eq!(reply.value["block"], hex::encode(id));
    let retried = client
        .send(address, &request, Duration::from_secs(5))
        .unwrap();
    assert_eq!(retried, reply);
    let confirmation = client
        .prepare(
            2,
            ingress::now().unwrap() + 60,
            ingress::Request::Confirm {
                transaction: hex::encode(trnm_protocol::pon_wire::hash(
                    b"tx-id",
                    &[&packet.transactions[0]],
                )),
                block: hex::encode(id),
            },
        )
        .unwrap();
    let confirmed = client
        .send(address, &confirmation, Duration::from_secs(5))
        .unwrap();
    assert!(confirmed.ok, "PQ confirmation refused: {}", confirmed.value);
    assert_eq!(confirmed.value["reorged"], false);
    assert_eq!(confirmed.value["confirmed"], false);
    assert_eq!(confirmed.value["finalized"], false);
    stop.store(true, Ordering::Release);
    let metrics = running.join().unwrap();
    assert_eq!(metrics.accepted, 3);
    let reopened = Node::open_with_pq_network(dir.path(), settings, 1, &policy).unwrap();
    let state = reopened.state_at(id).unwrap();
    assert_eq!(
        state[&format!("account:{}", hex::encode(f.active[0]))]["nonce"],
        23
    );
    assert_eq!(reopened.pq_network_status(&policy).unwrap()["records"], 2);
}

#[test]
fn open_pon_reward_address_gets_no_implicit_pq_spending_key() {
    let f = account_cases::fixture_at(ingress::now().unwrap() - 1000);
    let (settings, policy) = context(&f);
    let directory = tempfile::tempdir().unwrap();
    let mut node =
        Node::open_with_pq_network(directory.path(), settings.clone(), 1, &policy).unwrap();
    let beneficiary = trnm_pon_node::development_public(0).unwrap();
    let (app, _) = pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence)
        .unwrap()
        .into_execution_parts();
    let maturity = app.params["reward_maturity_blocks"].as_u64().unwrap();
    let mut parent = settings.genesis();
    for height in 1..=maturity + 1 {
        let packet = node
            .make(
                parent,
                vec![],
                beneficiary,
                settings.genesis_time() + 10 * height,
                4096,
            )
            .unwrap();
        parent = node.admit(&packet, ingress::now().unwrap()).unwrap();
        node.activate(parent).unwrap();
    }
    let state = node.state_at(parent).unwrap();
    assert!(
        state[&format!("account:{}", hex::encode(beneficiary))]["balance"]
            .as_u64()
            .unwrap()
            > 0
    );
    let mut forged = account_cases::transfer(&f, 0, 1, 1);
    forged.sender = beneficiary;
    let result = node.make(
        parent,
        vec![account_cases::signed(&f, &forged, 0)],
        beneficiary,
        settings.genesis_time() + 10 * (maturity + 2),
        4096,
    );
    assert!(result.is_err());
    assert_eq!(node.state_at(parent).unwrap(), state);
    println!(
        "{}",
        serde_json::json!({"case":"open_pon_reward_no_spending_authority",
        "full_work_blocks":maturity + 1,"unlisted_reward_balance_positive":true,
        "roster_mining_permission_required":false,"unlisted_spend_accepted":false})
    );
}
