#![cfg(all(unix, feature = "pq-native-openssl"))]
use openssl::pkey::PKey;
use serde_json::Value;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::Command,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use trnm_pon_node::{
    ingress::{
        pq_network::{
            tls::{PqTlsClient, PqTlsIdentity, PqTlsServer},
            PqNetworkPolicy, PqTlsPins,
        },
        Request,
    },
    Settings,
};
#[allow(dead_code)]
#[path = "../src/ingress/pq_network/tls/fixtures.rs"]
mod fixtures;
#[path = "pq_tls_witness_cli/support.rs"]
mod support;
use fixtures::Fixture;
use support::{command, put, snapshot, Running, Witness};

#[test]
fn witness_selected_binary_dispatches_replays_reopens_and_rejects_old_database() {
    let fixture = Fixture::new();
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let directory = tempfile::tempdir().unwrap();
    let create = witness.config(&fixture, "create");
    let (running, _) = Running::start(command(
        &fixture,
        directory.path(),
        &create,
        Some(&witness.writer),
    ));
    running.finish();
    let node = directory.path().join("node");
    let old = snapshot(&node);
    assert!(!old.is_empty());
    let before = witness.current(&fixture.policy);
    let reopen = witness.config(&fixture, "open_existing");
    let (running, ready) = Running::start(command(
        &fixture,
        directory.path(),
        &reopen,
        Some(&witness.writer),
    ));
    let address = ready["listen"].as_str().unwrap().parse().unwrap();
    let client = fixture.client();
    let request = client
        .prepare(
            1,
            trnm_pon_node::ingress::now().unwrap() + 60,
            Request::Head,
        )
        .unwrap();
    let receipt = client
        .send(address, &request, Duration::from_secs(5))
        .unwrap();
    assert!(receipt.ok);
    assert_eq!(receipt.value["height"], 0);
    assert_eq!(
        client
            .send(address, &request, Duration::from_secs(5))
            .unwrap(),
        receipt
    );
    let report = running.finish();
    assert_eq!(report["metrics"]["accepted"], 2);
    let after = witness.current(&fixture.policy);
    assert!(after.sequence > before.sequence);
    assert_ne!(after.root, before.root);
    // A real process reopen retains both the external frontier and exact reply.
    let (running, ready) = Running::start(command(
        &fixture,
        directory.path(),
        &reopen,
        Some(&witness.writer),
    ));
    let address = ready["listen"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        client
            .send(address, &request, Duration::from_secs(5))
            .unwrap(),
        receipt
    );
    running.finish();
    let retained = witness.current(&fixture.policy);
    // Restore the complete closed Node directory. The independent service and
    // its database stay live, including its later resource/request checkpoints.
    fs::remove_dir_all(&node).unwrap();
    fs::create_dir(&node).unwrap();
    for (path, bytes, mode) in old {
        let path = node.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        put(&path, &bytes, mode);
    }
    let output = command(&fixture, directory.path(), &reopen, Some(&witness.writer))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "old database published listener readiness"
    );
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_WITNESS"));
    assert_eq!(witness.current(&fixture.policy), retained);
}

#[test]
fn witness_schema_identity_and_private_key_refusals_precede_owner_and_witness_io() {
    let fixture = Fixture::new();
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let other = fixtures::key(95);
    let classical = PKey::generate_ed25519().unwrap();
    for fault in 0..13 {
        let directory = tempfile::tempdir().unwrap();
        let mut config = witness.config(&fixture, "create");
        let mut key = &witness.writer;
        match fault {
            0 => {
                config.as_object_mut().unwrap().remove("witness");
            }
            1 => config["schema"] = "native-pq-tls-loopback-config-v1".into(),
            2 => config["witness"]["generation"] = 0.into(),
            3 => config["witness"]["witness_spki"] = config["witness"]["writer_spki"].clone(),
            4 => key = &other,
            5 => {
                config["witness"]["writer_spki"] =
                    hex::encode(classical.public_key_to_der().unwrap()).into();
                key = &classical;
            }
            6 => config["witness"]["node_mode"] = "automatic".into(),
            7 => config["witness"]["auto_enroll"] = true.into(),
            8 => {}
            9 => {
                config["schema"] = "native-pq-tls-loopback-config-v1".into();
                config["witness"] = Value::Null;
            }
            10 => {}
            11 => config["schema"] = "native-pq-tls-loopback-config-v1".into(),
            12 => {
                config["schema"] = "native-pq-tls-loopback-config-v1".into();
                config.as_object_mut().unwrap().remove("witness");
            }
            _ => unreachable!(),
        }
        let writer_key = if matches!(fault, 9..=11) {
            None
        } else {
            Some(key)
        };
        let mut process = command(&fixture, directory.path(), &config, writer_key);
        if fault == 8 {
            fs::set_permissions(
                directory.path().join("writer.pem"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let output = process.output().unwrap();
        assert!(!output.status.success(), "accepted fault {fault}");
        assert!(output.stdout.is_empty(), "ready after fault {fault}");
        assert!(
            !directory.path().join("node").exists(),
            "created owner for fault {fault}"
        );
    }
    assert_eq!(witness.calls.load(Ordering::Acquire), 0);
}

#[test]
fn witness_existing_mode_never_creates_or_reenrolls_and_create_never_reopens() {
    let fixture = Fixture::new();
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let directory = tempfile::tempdir().unwrap();
    let reopen = witness.config(&fixture, "open_existing");
    let output = command(&fixture, directory.path(), &reopen, Some(&witness.writer))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_WITNESS_EXISTING_NODE_REQUIRED"));
    assert!(!directory.path().join("node").exists());
    assert_eq!(witness.calls.load(Ordering::Acquire), 0);
    let create = witness.config(&fixture, "create");
    let (running, _) = Running::start(command(
        &fixture,
        directory.path(),
        &create,
        Some(&witness.writer),
    ));
    running.finish();
    let prior = witness.current(&fixture.policy);
    let output = command(&fixture, directory.path(), &create, Some(&witness.writer))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_WITNESS_NEW_NODE_REQUIRED"));
    assert_eq!(witness.current(&fixture.policy), prior);
    // Changing the explicitly selected config cannot downgrade an existing
    // witness namespace to the old development TLS or classical backend.
    let mut legacy = create.clone();
    legacy["schema"] = "native-pq-tls-loopback-config-v1".into();
    legacy.as_object_mut().unwrap().remove("witness");
    let output = command(&fixture, directory.path(), &legacy, None)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "serve",
            "--development",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "1",
        ])
        .arg("--store")
        .arg(directory.path().join("node"))
        .arg("--genesis-time")
        .arg(fixture.settings.genesis_time().to_string())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(witness.current(&fixture.policy), prior);
}

#[test]
fn witness_missing_and_backlogged_endpoints_refuse_without_owner_or_listener() {
    use rustix::net::{
        connect, listen, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };
    let fixture = Fixture::new();
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let full_path = independent.path().join("full.sock");
    let listener = UnixListener::bind(&full_path).unwrap();
    listen(&listener, 1).unwrap();
    let address = SocketAddrUnix::new(&full_path).unwrap();
    let mut held = Vec::new();
    let mut full = false;
    for _ in 0..8 {
        #[cfg(not(target_vendor = "apple"))]
        let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
        #[cfg(target_vendor = "apple")]
        let flags = SocketFlags::empty();
        let socket = socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None).unwrap();
        #[cfg(target_vendor = "apple")]
        {
            let flags = rustix::io::fcntl_getfd(&socket).unwrap();
            rustix::io::fcntl_setfd(&socket, flags | rustix::io::FdFlags::CLOEXEC).unwrap();
            let flags = rustix::fs::fcntl_getfl(&socket).unwrap();
            rustix::fs::fcntl_setfl(&socket, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
        }
        match connect(&socket, &address) {
            Ok(()) => held.push(socket),
            Err(_) => {
                full = true;
                break;
            }
        }
    }
    assert!(full, "fixture did not reach a full Unix listener backlog");
    for endpoint in [independent.path().join("absent.sock"), full_path] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = witness.config(&fixture, "create");
        config["witness"]["socket"] = endpoint.to_str().unwrap().into();
        let start = Instant::now();
        let output = command(&fixture, directory.path(), &config, Some(&witness.writer))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("PQ_TLS_WITNESS_CONNECT"));
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "blocked on Unix connect"
        );
        assert!(output.stdout.is_empty());
        assert!(!directory.path().join("node").exists());
    }
    assert_eq!(witness.calls.load(Ordering::Acquire), 0);
}

#[test]
fn witness_wrong_authenticated_service_binding_cannot_publish_ready_or_advance() {
    let fixture = Fixture::new();
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let directory = tempfile::tempdir().unwrap();
    let prior = witness.current(&fixture.policy);
    let observed = witness.calls.load(Ordering::Acquire);
    let mut config: Value = witness.config(&fixture, "create");
    config["witness"]["witness_spki"] =
        hex::encode(fixtures::key(96).public_key_to_der().unwrap()).into();
    let output = command(&fixture, directory.path(), &config, Some(&witness.writer))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_WITNESS"));
    assert!(witness.calls.load(Ordering::Acquire) > observed);
    assert_eq!(witness.current(&fixture.policy), prior);
}
