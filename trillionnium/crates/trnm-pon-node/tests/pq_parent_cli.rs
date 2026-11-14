#![cfg(all(target_os = "linux", feature = "pq-native-openssl"))]
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
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
#[path = "pq_parent_cli/support.rs"]
mod support;
use support::{history_policy, outcome, pair, put, recovery, replace_arg, Running};

#[test]
fn ordinary_paired_tls_and_history_observe_one_actual_node_without_plaintext_native_fallback() {
    let fixture = Fixture::new();
    let builder_dir = tempfile::tempdir().unwrap();
    let builder = Node::open_with_pq_network(
        builder_dir.path(),
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let packet = builder
        .make(
            fixture.settings.genesis(),
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let expected = packet.id().unwrap();
    drop(builder);
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("node");
    let (running, ready) = Running::start(pair(&fixture, directory.path(), &store));
    let address = ready["native_listen"].as_str().unwrap().parse().unwrap();
    // Binding sockets does not establish History's actual Node/CPU owner.
    // A real pinned Head must complete its original startup before mutations.
    let startup_identity = PqPublicIdentity::from_signing_key(fixture.peer.signer());
    let (startup, _) = call_public_history_pq_v4(
        ready["history_listen"].as_str().unwrap().parse().unwrap(),
        &HistoryRequest::Head,
        &fixture.settings,
        &fixture.server.key.public_key_to_der().unwrap(),
        fixture.server.signer().public_key_id(),
        &startup_identity,
        history_policy(),
        Some(Instant::now() + Duration::from_secs(5)),
    );
    let startup = startup.unwrap();
    assert!(startup.ok);
    assert_eq!(startup.value["height"], 0);
    assert_eq!(
        startup.value["tip"],
        hex::encode(fixture.settings.genesis())
    );
    let client = fixture.client();
    let request = client
        .prepare(
            1,
            trnm_pon_node::ingress::now().unwrap() + 60,
            Request::Submit {
                packet: hex::encode(packet.encode_for_settings(&fixture.settings).unwrap()),
            },
        )
        .unwrap();
    let first = client
        .send(address, &request, Duration::from_secs(5))
        .unwrap();
    assert!(first.ok);
    assert_eq!(first.value["block"], hex::encode(expected));
    assert_eq!(
        client
            .send(address, &request, Duration::from_secs(5))
            .unwrap(),
        first
    );
    let identity = PqPublicIdentity::from_signing_key(fixture.peer.signer());
    let (reply, _) = call_public_history_pq_v4(
        ready["history_listen"].as_str().unwrap().parse().unwrap(),
        &HistoryRequest::Head,
        &fixture.settings,
        &fixture.server.key.public_key_to_der().unwrap(),
        fixture.server.signer().public_key_id(),
        &identity,
        history_policy(),
        Some(Instant::now() + Duration::from_secs(5)),
    );
    let reply = reply.unwrap();
    assert!(reply.ok);
    assert_eq!(reply.value["height"], 1);
    // A plaintext framing attempt reaches the actual TLS listener and cannot
    // spend a native sequence, even with an otherwise valid signed wire.
    let mut plain = std::net::TcpStream::connect(address).unwrap();
    use std::io::{Read, Write};
    plain
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    plain.write_all(request.wire()).unwrap();
    plain.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    let _ = plain.read_to_end(&mut response);
    drop(plain);
    let report = running.finish();
    assert_eq!(report["native_metrics"]["accepted"], 2);
    let node =
        Node::open_with_pq_network(&store, fixture.settings.clone(), 1, &fixture.policy).unwrap();
    assert_eq!(node.active().unwrap().0, expected);
    assert_eq!(
        node.pq_network_status(&fixture.policy).unwrap()["records"],
        1
    );
}

#[test]
fn ordinary_create_recovers_real_parent_and_resume_keeps_original_campaign_and_pins() {
    let fixture = Fixture::new();
    let source = tempfile::tempdir().unwrap();
    let producer_store = source.path().join("node");
    let mut producer = Node::open_with_pq_network(
        &producer_store,
        fixture.settings.clone(),
        1,
        &fixture.policy,
    )
    .unwrap();
    let parent = producer
        .make(
            fixture.settings.genesis(),
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let parent_id = producer
        .admit(&parent, trnm_pon_node::ingress::now().unwrap())
        .unwrap();
    producer
        .activate_observed(parent_id, trnm_pon_node::ingress::now().unwrap())
        .unwrap();
    let target = producer
        .make(
            parent_id,
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            fixture.settings.genesis_time() + 20,
            4096,
        )
        .unwrap();
    let target_id = target.id().unwrap();
    let admitted_target = producer
        .admit(&target, trnm_pon_node::ingress::now().unwrap())
        .unwrap();
    assert_eq!(admitted_target, target_id);
    producer
        .activate_observed(target_id, trnm_pon_node::ingress::now().unwrap())
        .unwrap();
    let target_path = source.path().join("target.npq");
    put(
        &target_path,
        &target.encode_for_settings(&fixture.settings).unwrap(),
        false,
    );
    drop(producer);
    let remote = tempfile::tempdir().unwrap();
    let remote_store = remote.path().join("node");
    let (running, ready) = Running::start(pair(&fixture, remote.path(), &remote_store));
    let caller_files = tempfile::tempdir().unwrap();
    let campaign = source.path().join("campaign");
    let created = outcome(recovery(
        &fixture,
        caller_files.path(),
        &producer_store,
        &campaign,
        &target_path,
        &ready,
        false,
    ));
    assert_eq!(created["may_advance_dependency"], true);
    assert_eq!(created["membership_observed"], true);
    let before: Value =
        serde_json::from_slice(&fs::read(campaign.join("journal")).unwrap()).unwrap();
    let resumed = outcome(recovery(
        &fixture,
        caller_files.path(),
        &producer_store,
        &campaign,
        &target_path,
        &ready,
        true,
    ));
    assert_eq!(resumed["may_advance_dependency"], true);
    assert!(
        resumed["reserved_calls"].as_u64().unwrap() >= created["reserved_calls"].as_u64().unwrap()
    );
    let after: Value =
        serde_json::from_slice(&fs::read(campaign.join("journal")).unwrap()).unwrap();
    assert_eq!(before["epoch"], after["epoch"]);
    assert_eq!(before["binding"], after["binding"]);
    // An independently supplied, valid loopback endpoint cannot replace the
    // original context on cold resume, and the denied attempt opens no socket.
    let alternate = TcpListener::bind("127.0.0.1:0").unwrap();
    alternate.set_nonblocking(true).unwrap();
    let mut altered = ready.clone();
    altered["native_listen"] = alternate.local_addr().unwrap().to_string().into();
    let stable = fs::read(campaign.join("journal")).unwrap();
    let output = recovery(
        &fixture,
        caller_files.path(),
        &producer_store,
        &campaign,
        &target_path,
        &altered,
        true,
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(matches!(alternate.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(fs::read(campaign.join("journal")).unwrap(), stable);
    // Resume accepts no new plan knobs; the original epoch/counters survive.
    let mut renewed = recovery(
        &fixture,
        caller_files.path(),
        &producer_store,
        &campaign,
        &target_path,
        &ready,
        true,
    );
    renewed.args(["--submit-deadline-ms", "60000"]);
    let output = renewed.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PQ_PARENT_OPTION"));
    assert_eq!(fs::read(campaign.join("journal")).unwrap(), stable);
    running.finish();
    let node =
        Node::open_with_pq_network(&remote_store, fixture.settings.clone(), 1, &fixture.policy)
            .unwrap();
    assert_eq!(node.active().unwrap().0, target_id);
}

#[test]
fn ordinary_parent_nonloopback_and_resume_plan_options_refuse_before_protected_inputs() {
    for (command, options, expected) in [
        (
            "pq-parent-tls-serve",
            vec![
                "--native-listen",
                "192.0.2.1:1",
                "--history-listen",
                "127.0.0.1:2",
            ],
            "PQ_PARENT_RECOVERY_LOOPBACK_ONLY",
        ),
        (
            "pq-parent-create",
            vec![
                "--native-peer",
                "127.0.0.1:1",
                "--history-peer",
                "192.0.2.1:2",
            ],
            "PQ_PARENT_RECOVERY_LOOPBACK_ONLY",
        ),
        (
            "pq-parent-resume",
            vec!["--submit-call-cap", "64"],
            "PQ_PARENT_OPTION",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
            .args([command, "--development"])
            .args(options)
            .arg("--store")
            .arg(directory.path().join("node"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        assert!(output.stdout.is_empty());
        assert!(!directory.path().join("node").exists());
    }
}

#[test]
fn ordinary_parent_configuration_peer_and_history_pins_refuse_before_owner_creation() {
    let fixture = Fixture::new();
    for fault in 0..8 {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("node");
        let mut process = pair(&fixture, directory.path(), &store);
        match fault {
            0 => {
                let mut bytes = fs::read(directory.path().join("config.json")).unwrap();
                bytes.push(b' ');
                put(&directory.path().join("config.json"), &bytes, false);
            }
            1 => {
                put(
                    &directory.path().join("key.pem"),
                    &fixture.peer.key.private_key_to_pem_pkcs8().unwrap(),
                    true,
                );
            }
            2 => {
                put(
                    &directory.path().join("identity.pem"),
                    &fixture.other.certificate.to_pem().unwrap(),
                    false,
                );
            }
            3 => {
                process.args(["--campaign", "/unselected-campaign"]);
            }
            4 => {
                let mut config: Value = serde_json::from_slice(
                    &fs::read(directory.path().join("config.json")).unwrap(),
                )
                .unwrap();
                config["witness"] = Value::Null;
                // Updating the explicit outer pin does not admit a present-null
                // witness or silently select the legacy schema.
                let raw = serde_json::to_vec(&config).unwrap();
                put(&directory.path().join("config.json"), &raw, false);
                use sha2::{Digest, Sha256};
                process = replace_arg(
                    process,
                    "--tls-config-sha256",
                    hex::encode(Sha256::digest(&raw)),
                );
            }
            5 => {
                process = replace_arg(process, "--history-policy-sha256", "00".repeat(32));
            }
            6 => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    directory.path().join("key.pem"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            7 => {
                let original = directory.path().join("config.json");
                let moved = directory.path().join("retained-config.json");
                fs::rename(&original, &moved).unwrap();
                std::os::unix::fs::symlink(&moved, &original).unwrap();
            }
            _ => unreachable!(),
        }
        let output = process.output().unwrap();
        assert!(!output.status.success(), "accepted fault {fault}");
        assert!(output.stdout.is_empty());
        assert!(!store.exists());
    }
}
