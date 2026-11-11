//! Real ordinary binary controls; fixture construction is not consumer qualification.
#![cfg(all(target_os = "linux", feature = "pq-native-openssl"))]
use serde_json::Value;
use std::fs;
use trnm_pon_node::{
    ingress::pq_network::{
        tls::{PqTlsClient, PqTlsIdentity, PqTlsServer},
        PqNetworkPolicy, PqTlsPins,
    },
    Node, Settings,
};
#[allow(dead_code)]
#[path = "../src/ingress/pq_network/tls/fixtures.rs"]
mod fixtures;
use fixtures::Fixture;
#[path = "pq_application_local_cli/fixture.rs"]
mod fixture;
use fixture::{exchange, Application};
#[path = "pq_application_local_cli/export.rs"]
mod export;

#[test]
fn ordinary_npq6_submit_and_cold_status_execute_current_task_and_evaluator_roles() {
    let app = Application::new();
    let root = tempfile::tempdir().unwrap();
    let mut producer = app.open(&root.path().join("producer"));
    let samples = app.samples(&mut producer);
    // Full, actually signed NPQ6 command/evidence envelopes still parse to the
    // exact original packet bytes through the optimized once-only preflight.
    for (index, packet) in samples.packets.iter().enumerate() {
        let bytes = packet.encode_for_settings(&app.tls.settings).unwrap();
        let decoded =
            trnm_pon_node::Packet::decode_for_settings(&bytes, &app.tls.settings).unwrap();
        assert_eq!(
            decoded.encode_for_settings(&app.tls.settings).unwrap(),
            bytes,
            "signed packet {index}"
        );
    }
    app.assert_task_and_evaluator_state(&producer, &samples);
    drop(producer);
    let directory = root.path().join("receiver");
    let mut receiver = app.open(&directory);
    let now = trnm_pon_node::ingress::now().unwrap();
    let lease = receiver.admit(&samples.packets[0], now).unwrap();
    receiver.activate_observed(lease, now).unwrap();
    drop(receiver);
    let before = app.call(
        root.path(),
        &directory,
        "packet-status",
        &samples.packets[1],
    );
    assert_eq!(before["result"]["stored_exact"], false);
    let receipt = app.call(root.path(), &directory, "submit", &samples.packets[1]);
    assert_eq!(
        receipt["result"]["block"],
        hex::encode(samples.packets[1].id().unwrap())
    );
    let after = app.call(
        root.path(),
        &directory,
        "packet-status",
        &samples.packets[1],
    );
    assert_eq!(after["result"]["stored_exact"], true);
    assert_eq!(after["result"]["active_chain_member"], true);
    // Complete the intervening real signed account history with the public
    // owner API; the second ordinary subprocess consumes the evaluator frame.
    let mut receiver = app.open(&directory);
    for packet in &samples.packets[2..15] {
        let id = receiver.admit(packet, now).unwrap();
        receiver.activate_observed(id, now).unwrap();
    }
    drop(receiver);
    let before = app.call(
        root.path(),
        &directory,
        "packet-status",
        &samples.packets[15],
    );
    assert_eq!(before["result"]["stored_exact"], false);
    app.call(root.path(), &directory, "submit", &samples.packets[15]);
    let cold = app.call(
        root.path(),
        &directory,
        "packet-status",
        &samples.packets[15],
    );
    assert_eq!(cold["result"]["stored_exact"], true);
    assert_eq!(cold["result"]["active_chain_member"], true);
    let receiver = app.open(&directory);
    app.assert_task_and_evaluator_state(&receiver, &samples);
}

#[test]
fn ordinary_npq6_configuration_rejects_missing_null_extra_and_mixed_bindings() {
    let app = Application::new();
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("receiver");
    drop(app.open(&directory));
    let database = fs::read(directory.join("native.sqlite")).unwrap();
    let mut producer = app.open(&root.path().join("producer"));
    let packet = producer
        .make_consensus_maintenance(
            app.tls.settings.genesis(),
            vec![],
            app.ids[0],
            app.tls.settings.genesis_time() + 50,
            4096,
        )
        .unwrap();
    let now = trnm_pon_node::ingress::now().unwrap();
    let block = producer.admit(&packet, now).unwrap();
    producer.activate_observed(block, now).unwrap();
    let raw = packet.encode_for_settings(&app.tls.settings).unwrap();
    assert!(raw.starts_with(b"PQP6"));
    drop(producer);
    for fault in 0..12 {
        let mut config = app.configuration();
        match fault {
            0 => {
                config.as_object_mut().unwrap().remove("owner_profile");
            }
            1 => config["owner_profile"] = Value::Null,
            2 => config["network"] = serde_json::json!("11".repeat(32)),
            3 => config["parameters"] = serde_json::json!("12".repeat(32)),
            4 => config["genesis"] = serde_json::json!("13".repeat(32)),
            5 => config["network_policy"] = serde_json::json!("14".repeat(32)),
            6 => config["witness"] = Value::Null,
            7 => config["accounts"][0]["unknown"] = Value::Bool(true),
            8 => config["application"]["unknown"] = Value::Bool(true),
            9 => {
                config.as_object_mut().unwrap().remove("network_policy");
            }
            10 => config["schema"] = serde_json::json!("native-pq-application-local-config-v2"),
            11 => config["owner_profile"] = serde_json::json!("witness_v4"),
            _ => unreachable!(),
        }
        let output = exchange(
            app.command(root.path(), &directory, "submit", &config),
            &raw,
        );
        assert!(!output.status.success(), "fault {fault}");
        let expected = match fault {
            0 => "missing field `owner_profile`",
            // serde_json's externally tagged enum reader rejects JSON null
            // before visiting OwnerProfile; the optional witness uses its
            // separate explicit-present deserializer. Both refusals must
            // precede opening or mutating the owner, as checked below.
            1 => "expected value",
            6 => "invalid type: null",
            2..=4 => "PQ_NETWORK_CONTEXT",
            5 => "PQ_APPLICATION_NETWORK_POLICY",
            7 | 8 => "unknown field `unknown`",
            9 => "missing field `network_policy`",
            10 => "PQ_APPLICATION_CONFIG_SCHEMA",
            11 => "PQ_TLS_WITNESS_CONFIG_REQUIRED",
            _ => unreachable!(),
        };
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "fault {fault}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("pq_application_context"));
        assert_eq!(fs::read(directory.join("native.sqlite")).unwrap(), database);
        assert!(!directory.join("initializing.json").exists());
    }
    let command = app.command_with_pin(
        root.path(),
        &directory,
        "submit",
        &app.configuration(),
        Some(&"00".repeat(32)),
    );
    assert_eq!(
        command
            .get_args()
            .filter(|arg| *arg == "--pq-application-config-sha256")
            .count(),
        1
    );
    let output = exchange(command, &raw);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PQ_APPLICATION_CONFIG_PIN"));
    assert_eq!(fs::read(directory.join("native.sqlite")).unwrap(), database);
    app.call(root.path(), &directory, "submit", &packet);
    assert_eq!(
        app.call(root.path(), &directory, "packet-status", &packet)["result"]["stored_exact"],
        true
    );
}

#[test]
fn ordinary_npq6_refuses_existing_owner_context_and_never_creates_a_missing_owner() {
    let app = Application::new();
    let root = tempfile::tempdir().unwrap();
    let mut producer = app.open(&root.path().join("producer"));
    let samples = app.samples(&mut producer);
    let raw = samples.packets[0]
        .encode_for_settings(&app.tls.settings)
        .unwrap();
    drop(producer);
    let absent = root.path().join("absent");
    let result = exchange(
        app.command(root.path(), &absent, "submit", &app.configuration()),
        &raw,
    );
    assert!(!result.status.success());
    assert!(!absent.exists());
    let incompatible = root.path().join("other-owner");
    let changed = PqNetworkPolicy::new_tls13(
        &app.tls.settings,
        app.tls.server.signer().public_spki(),
        2,
        [
            app.tls.peer.signer().public_spki().to_vec(),
            app.tls.other.signer().public_spki().to_vec(),
        ],
        app.tls.policy.tls_pins().unwrap().clone(),
    )
    .unwrap();
    drop(Node::open_with_pq_network(&incompatible, app.tls.settings.clone(), 1, &changed).unwrap());
    let database = fs::read(incompatible.join("native.sqlite")).unwrap();
    let result = exchange(
        app.command(root.path(), &incompatible, "submit", &app.configuration()),
        &raw,
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("pq_application_context"));
    assert_eq!(
        fs::read(incompatible.join("native.sqlite")).unwrap(),
        database
    );
    let owner =
        Node::open_existing_with_pq_network(&incompatible, app.tls.settings.clone(), 1, &changed)
            .unwrap();
    assert_eq!(
        owner.exact_packet_observation(&samples.packets[0]).unwrap()["stored_exact"],
        false
    );
}

#[test]
fn ordinary_npq6_invalid_packet_encoding_cannot_fall_back_to_classical_settings() {
    let app = Application::new();
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("receiver");
    drop(app.open(&directory));
    let database = fs::read(directory.join("native.sqlite")).unwrap();
    let classic = Settings::development(Some(app.tls.settings.genesis_time())).unwrap();
    let mut producer = Node::open(&root.path().join("classic"), classic.clone(), 1).unwrap();
    let packet = producer
        .make(
            classic.genesis(),
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            classic.genesis_time() + 50,
            4096,
        )
        .unwrap();
    let now = trnm_pon_node::ingress::now().unwrap();
    let block = producer.admit(&packet, now).unwrap();
    producer.activate_observed(block, now).unwrap();
    assert_eq!(
        producer.exact_packet_observation(&packet).unwrap()["stored_exact"],
        true
    );
    let classic_raw = packet.encode_for_settings(&classic).unwrap();
    assert!(!classic_raw.starts_with(b"PQP6"));
    // A valid original Development packet is a stronger refusal control than
    // junk that both codecs would reject; the positive above used real owners.
    for command in ["submit", "packet-status"] {
        for bytes in [
            classic_raw.as_slice(),
            b"PNQ3-not-an-NPQ6-packet".as_slice(),
        ] {
            let output = exchange(
                app.command(root.path(), &directory, command, &app.configuration()),
                bytes,
            );
            assert!(!output.status.success());
            assert!(!String::from_utf8_lossy(&output.stdout).contains("pq_application_context"));
            assert_eq!(fs::read(directory.join("native.sqlite")).unwrap(), database);
        }
    }
}
