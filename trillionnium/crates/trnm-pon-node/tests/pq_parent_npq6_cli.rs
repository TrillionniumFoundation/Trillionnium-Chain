#![cfg(all(target_os = "linux", feature = "pq-native-openssl"))]
use serde_json::Value;
use std::{
    fs,
    time::{Duration, Instant},
};
use trnm_pon_node::{
    ingress::{
        pq_network::{
            tls::{PqTlsClient, PqTlsIdentity, PqTlsServer},
            PqNetworkPolicy, PqTlsPins,
        },
        public_v3::{
            call_public_history_pq_v4, PqPublicIdentity, PublicPolicy, Request as HistoryRequest,
        },
        Request,
    },
    public_submit::pq::PQ_RECOVERY_HISTORY_TRANSPORT,
    Node, Settings,
};
#[allow(dead_code)]
#[path = "../src/ingress/pq_network/tls/fixtures.rs"]
mod fixtures;
use fixtures::Fixture;
#[path = "pq_parent_npq6_cli/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "pq_parent_cli/support.rs"]
mod support;
#[allow(dead_code)]
#[path = "pq_tls_witness_cli/support.rs"]
mod witness_support;
use fixture::Profile;
use support::{outcome, put, Running};

#[test]
fn ordinary_npq6_create_recovers_signed_account_parent_and_cold_resume_retains_epoch() {
    let profile = Profile::new();
    let source = tempfile::tempdir().unwrap();
    let producer_store = source.path().join("node");
    let mut producer = Node::open_with_pq_network(
        &producer_store,
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy,
    )
    .unwrap();
    let packets = profile.packets(&mut producer, 2);
    let parent = packets[0].id().unwrap();
    let target = packets[1].id().unwrap();
    let raw = packets[1]
        .encode_for_settings(&profile.tls.settings)
        .unwrap();
    assert!(raw.starts_with(b"PQP6"));
    let packet_path = source.path().join("target.npq6");
    put(&packet_path, &raw, false);
    drop(producer);
    let remote = tempfile::tempdir().unwrap();
    let remote_store = remote.path().join("node");
    let (running, bound) = Running::start(profile.pair(remote.path(), &remote_store));
    // The event only proves bound sockets; a real pinned paid Head proves the
    // original History/Node owner has completed startup before any mutation.
    let head = profile.head(&bound);
    assert_eq!(head["height"], 0);
    assert_eq!(head["tip"], hex::encode(profile.tls.settings.genesis()));
    let files = tempfile::tempdir().unwrap();
    let campaign = source.path().join("campaign");
    let created = outcome(profile.recover(
        files.path(),
        &producer_store,
        &campaign,
        &packet_path,
        &bound,
        false,
    ));
    assert_eq!(created["membership_observed"], true);
    assert_eq!(created["may_advance_dependency"], true);
    assert_eq!(created["submission_outcome_uncertain"], false);
    assert!(created["pending"].is_null());
    assert_eq!(
        created["network"],
        hex::encode(profile.tls.settings.network())
    );
    assert_eq!(
        created["parameters"],
        hex::encode(profile.tls.settings.parameters())
    );
    assert_eq!(
        created["genesis"],
        hex::encode(profile.tls.settings.genesis())
    );
    assert_eq!(
        created["restored_parent_memberships"],
        serde_json::json!([hex::encode(parent)])
    );
    let native: Vec<_> = created["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["kind"] == "native")
        .map(|row| &row["observation"])
        .collect();
    assert_eq!(
        native
            .iter()
            .map(|row| row["sequence"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        native
            .iter()
            .map(|row| row["packet"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            hex::encode(target),
            hex::encode(parent),
            hex::encode(target)
        ]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
    );
    assert_eq!(
        native[0]["authenticated_response"]["value"]["error"],
        "UNKNOWN_PARENT"
    );
    assert!(native.iter().all(|row| row["receipt_persisted"] == true
        && row["client_error"].is_null()
        && row["journal_error"].is_null()));
    let before: Value =
        serde_json::from_slice(&fs::read(campaign.join("journal")).unwrap()).unwrap();
    let resumed = outcome(profile.recover(
        files.path(),
        &producer_store,
        &campaign,
        &packet_path,
        &bound,
        true,
    ));
    assert_eq!(resumed["may_advance_dependency"], true);
    assert!(resumed["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["kind"] == "history"));
    assert!(
        resumed["reserved_calls"].as_u64().unwrap() > created["reserved_calls"].as_u64().unwrap()
    );
    let after: Value =
        serde_json::from_slice(&fs::read(campaign.join("journal")).unwrap()).unwrap();
    assert_eq!(before["epoch"], after["epoch"]);
    assert_eq!(before["binding"], after["binding"]);
    assert_eq!(before["operations"], after["operations"]);
    assert_eq!(profile.head(&bound)["tip"], hex::encode(target));
    let report = running.finish();
    assert_eq!(report["native_metrics"]["accepted"], 3);
    let remote = Node::open_with_pq_network(
        &remote_store,
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy,
    )
    .unwrap();
    assert_eq!(remote.active().unwrap().0, target);
    assert_eq!(
        remote.pq_network_status(&profile.tls.policy).unwrap()["records"],
        3
    );
    assert_eq!(
        remote
            .packet(target)
            .unwrap()
            .encode_for_settings(&profile.tls.settings)
            .unwrap(),
        raw
    );
}

#[test]
fn ordinary_npq6_witness_selection_dispatches_account_packet_without_owner_downgrade() {
    use std::os::unix::net::UnixStream;
    use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
    use trnm_pon_node::pq_rollback_witness::{
        ConnectedWitnessTransport, WitnessBinding, WitnessClient,
    };
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    let profile = Profile::new();
    let producer_dir = tempfile::tempdir().unwrap();
    let mut producer = Node::open_with_pq_network(
        producer_dir.path(),
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy,
    )
    .unwrap();
    let packet = profile.packets(&mut producer, 1).remove(0);
    let id = packet.id().unwrap();
    let raw = packet.encode_for_settings(&profile.tls.settings).unwrap();
    drop(producer);
    let custody = tempfile::tempdir().unwrap();
    let witness = witness_support::Witness::new(&profile.tls, custody.path());
    let before = witness.current(&profile.tls.policy);
    let files = tempfile::tempdir().unwrap();
    let store = files.path().join("node");
    let mut config = profile.configuration();
    config["owner_profile"] = "witness_v4".into();
    config["witness"] = witness.config(&profile.tls, "create")["witness"].clone();
    let command = profile.pair(files.path(), &store);
    let mut command = fixture::with_configuration(command, files.path(), &config);
    put(
        &files.path().join("writer.pem"),
        &witness.writer.private_key_to_pem_pkcs8().unwrap(),
        true,
    );
    command
        .arg("--witness-writer-key")
        .arg(files.path().join("writer.pem"));
    let (running, bound) = Running::start(command);
    assert_eq!(bound["pnq2_rollback_witness_selected"], true);
    assert_eq!(
        profile.head(&bound)["tip"],
        hex::encode(profile.tls.settings.genesis())
    );
    let client = profile.tls.client();
    let request = client
        .prepare(
            1,
            trnm_pon_node::ingress::now().unwrap() + 60,
            Request::Submit {
                packet: hex::encode(&raw),
            },
        )
        .unwrap();
    let address = bound["native_listen"].as_str().unwrap().parse().unwrap();
    let receipt = client
        .send(address, &request, Duration::from_secs(5))
        .unwrap();
    assert!(receipt.ok);
    assert_eq!(receipt.value["block"], hex::encode(id));
    assert_eq!(
        client
            .send(address, &request, Duration::from_secs(5))
            .unwrap(),
        receipt
    );
    assert_eq!(profile.head(&bound)["tip"], hex::encode(id));
    let report = running.finish();
    assert_eq!(report["native_metrics"]["accepted"], 2);
    assert_eq!(report["pnq2_rollback_witness_selected"], true);
    let after = witness.current(&profile.tls.policy);
    assert!(after.sequence > before.sequence);
    assert_ne!(after.root, before.root);
    assert!(Node::open_with_pq_network(
        &store,
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy
    )
    .is_err());
    let writer_spki = witness.writer.public_key_to_der().unwrap();
    let binding = WitnessBinding::new(
        &profile.tls.policy,
        1,
        &witness.witness.public_key_to_der().unwrap(),
        &writer_spki,
    )
    .unwrap();
    let writer = PqNativeSigningKey::from_owned_key(
        witness.writer.clone(),
        ml_dsa_65_key_id_from_spki(&writer_spki).unwrap(),
    )
    .unwrap();
    let owner = WitnessClient::new(
        binding,
        writer,
        Box::new(ConnectedWitnessTransport::new(
            UnixStream::connect(&witness.socket).unwrap(),
        )),
    )
    .unwrap();
    let reopened = Node::open_with_pq_witness(
        &store,
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy,
        owner,
    )
    .unwrap();
    assert_eq!(reopened.active().unwrap().0, id);
    assert_eq!(
        reopened
            .packet(id)
            .unwrap()
            .encode_for_settings(&profile.tls.settings)
            .unwrap(),
        raw
    );
}

#[path = "pq_parent_npq6_cli/negative.rs"]
mod negative;
