#![cfg(all(unix, feature = "pq-native-openssl"))]
use openssl::pkey::{PKey, Private};
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs,
    net::{IpAddr, SocketAddr, TcpListener},
    path::Path,
    process::{Command, Stdio},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use trnm_pon_node::{
    ingress::{
        pq_network::{
            tls::{PqTlsClient, PqTlsIdentity, PqTlsServer},
            PqNetworkPolicy, PqTlsEndpointPins, PqTlsPins, TLS_ENDPOINT_PROFILE,
        },
        Request,
    },
    Node, Settings,
};
#[allow(dead_code)]
#[path = "../src/ingress/pq_network/tls/fixtures.rs"]
mod fixtures;
#[path = "pq_tls_witness_cli/support.rs"]
mod support;
use fixtures::Fixture;
use support::{put, snapshot, Running, Witness};

fn endpoint_fixture(address: SocketAddr) -> Fixture {
    let mut fixture = Fixture::new();
    fixture.policy = Arc::new(
        PqNetworkPolicy::new_tls13_endpoint(
            &fixture.settings,
            &fixture.server.key.public_key_to_der().unwrap(),
            1,
            [
                fixture.peer.key.public_key_to_der().unwrap(),
                fixture.other.key.public_key_to_der().unwrap(),
            ],
            fixture.policy.tls_pins().unwrap().clone(),
            PqTlsEndpointPins::new(address, vec![IpAddr::from([127, 0, 0, 1])]).unwrap(),
        )
        .unwrap(),
    );
    fixture
}

fn config(fixture: &Fixture, witness: &Witness, mode: &str) -> Value {
    let mut value = witness.config(fixture, mode);
    value["schema"] = "native-pq-tls-pinned-endpoint-config-v1".into();
    value["endpoint"] = serde_json::to_value(fixture.policy.tls_endpoint_pins().unwrap()).unwrap();
    value
}

fn command(
    fixture: &Fixture,
    directory: &Path,
    configuration: &Value,
    writer: Option<&PKey<Private>>,
    address: SocketAddr,
    selected: bool,
) -> Command {
    // Reuse the original protected fixture writer. Replace its listen argument
    // instead of appending a duplicate option that the binary correctly rejects.
    let original = support::command(fixture, directory, configuration, writer);
    let mut args: Vec<OsString> = original.get_args().map(OsString::from).collect();
    let listen = args.iter().position(|arg| arg == "--listen").unwrap();
    args[listen + 1] = address.to_string().into();
    let seconds = args.iter().position(|arg| arg == "--seconds").unwrap();
    args[seconds + 1] = "5".into();
    let mut child = Command::new(original.get_program());
    child.args(args);
    if selected {
        child.args(["--tls-network-profile", "pinned-endpoint-v1"]);
    }
    child
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    child
}

#[test]
fn endpoint_schema_scope_and_witness_refusals_precede_all_owner_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = endpoint_fixture(address);
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    for fault in 0..21 {
        let directory = tempfile::tempdir().unwrap();
        let mut value = config(&fixture, &witness, "create");
        let mut selected = true;
        let mut key = Some(&witness.writer);
        let mut listen = address;
        match fault {
            0 => selected = false,
            1 => value["schema"] = "native-pq-tls-loopback-config-v2".into(),
            2 => value["schema"] = "native-pq-tls-loopback-config-v1".into(),
            3 => {
                value.as_object_mut().unwrap().remove("endpoint");
            }
            4 => value["endpoint"] = Value::Null,
            5 => {
                value.as_object_mut().unwrap().remove("witness");
            }
            6 => value["witness"] = Value::Null,
            7 => key = None,
            8 => value["endpoint"]["server_address"] = "0.0.0.0:32145".into(),
            9 => value["endpoint"]["server_address"] = "127.0.0.1:0".into(),
            10 => value["endpoint"]["allowed_client_ips"] = json!([]),
            11 => value["endpoint"]["allowed_client_ips"] = json!(["127.0.0.1", "127.0.0.1"]),
            12 => value["endpoint"]["allowed_client_ips"] = json!(["0.0.0.0"]),
            13 => value["endpoint"]["allowed_client_ips"] = json!(["224.0.0.1"]),
            14 => value["endpoint"]["allowed_client_ips"] = json!(["::ffff:127.0.0.1"]),
            15 => value["endpoint"]["allowed_client_ips"] = json!(["255.255.255.255"]),
            16 => listen.set_port(if address.port() == 65535 {
                65534
            } else {
                address.port() + 1
            }),
            17 => value["endpoint"]["unbound_override"] = true.into(),
            18 => {
                value["schema"] = "native-pq-tls-loopback-config-v2".into();
                selected = false;
            }
            19 | 20 => selected = false,
            _ => unreachable!(),
        }
        let mut process = command(&fixture, directory.path(), &value, key, listen, selected);
        if fault == 19 {
            process.args(["--tls-network-profile", "unknown-profile"]);
        } else if fault == 20 {
            process.arg("--tls-network-profile");
        }
        let output = process.output().unwrap();
        assert!(!output.status.success(), "accepted endpoint fault {fault}");
        assert!(
            output.stdout.is_empty(),
            "published ready for fault {fault}"
        );
        assert!(
            !directory.path().join("node").exists(),
            "created owner for fault {fault}"
        );
    }
    assert_eq!(witness.calls.load(Ordering::Acquire), 0);
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn endpoint_binary_dispatches_replays_recovers_and_rejects_old_database() {
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let fixture = endpoint_fixture(address);
    let builder_directory = tempfile::tempdir().unwrap();
    let builder_policy = fixture.policy_for_server_name("localhost");
    let builder = Node::open_with_pq_network(
        builder_directory.path(),
        fixture.settings.clone(),
        1,
        &builder_policy,
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
    let block = packet.id().unwrap();
    drop(builder);
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let directory = tempfile::tempdir().unwrap();
    let create = config(&fixture, &witness, "create");
    drop(reserved);
    let (running, ready) = Running::start(command(
        &fixture,
        directory.path(),
        &create,
        Some(&witness.writer),
        address,
        true,
    ));
    assert_eq!(ready["profile"], TLS_ENDPOINT_PROFILE);
    assert_eq!(ready["listen"], address.to_string());
    assert_eq!(ready["pinned_endpoint_development"], true);
    assert_eq!(ready["public_wan_qualification"], false);
    running.finish();
    let node = directory.path().join("node");
    let old = snapshot(&node);
    let reopen = config(&fixture, &witness, "open_existing");
    let (mut running, _) = Running::start(command(
        &fixture,
        directory.path(),
        &reopen,
        Some(&witness.writer),
        address,
        true,
    ));
    let client = fixture.client();
    let expiry = trnm_pon_node::ingress::now().unwrap() + 60;
    let head = client.prepare(1, expiry, Request::Head).unwrap();
    assert_eq!(
        running
            .observe("head", || client.send(
                address,
                &head,
                Duration::from_secs(5)
            ))
            .unwrap()
            .value["height"],
        0
    );
    let submit = client
        .prepare(
            2,
            expiry,
            Request::Submit {
                packet: hex::encode(packet.encode().unwrap()),
            },
        )
        .unwrap();
    let receipt = running
        .observe("submit", || {
            client.send(address, &submit, Duration::from_secs(5))
        })
        .unwrap();
    assert!(receipt.ok);
    assert_eq!(receipt.value["block"], hex::encode(block));
    assert_eq!(
        running
            .observe("submit_replay", || {
                client.send(address, &submit, Duration::from_secs(5))
            })
            .unwrap(),
        receipt
    );
    let history = client
        .prepare(
            3,
            expiry,
            Request::History {
                tip: hex::encode(block),
                after: hex::encode(fixture.settings.genesis()),
            },
        )
        .unwrap();
    let history_receipt = running
        .observe("history", || {
            client.send(address, &history, Duration::from_secs(5))
        })
        .unwrap();
    assert!(history_receipt.ok);
    assert_eq!(running.finish()["metrics"]["accepted"], 4);
    let before_reopen = witness.current(&fixture.policy);
    let (mut running, _) = Running::start(command(
        &fixture,
        directory.path(),
        &reopen,
        Some(&witness.writer),
        address,
        true,
    ));
    assert_eq!(
        running
            .observe("reopen_submit_replay", || {
                client.send(address, &submit, Duration::from_secs(5))
            })
            .unwrap(),
        receipt
    );
    running.finish();
    let retained = witness.current(&fixture.policy);
    assert!(retained.sequence > before_reopen.sequence);
    fs::remove_dir_all(&node).unwrap();
    fs::create_dir(&node).unwrap();
    for (path, bytes, mode) in old {
        let path = node.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        put(&path, &bytes, mode);
    }
    let output = command(
        &fixture,
        directory.path(),
        &reopen,
        Some(&witness.writer),
        address,
        true,
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PQ_WITNESS"));
    assert_eq!(witness.current(&fixture.policy), retained);
}

#[test]
fn endpoint_binary_rejects_legacy_policy_and_changed_endpoint_on_reopen() {
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let fixture = endpoint_fixture(address);
    let independent = tempfile::tempdir().unwrap();
    let witness = Witness::new(&fixture, independent.path());
    let directory = tempfile::tempdir().unwrap();
    let create = config(&fixture, &witness, "create");
    drop(reserved);
    let (running, _) = Running::start(command(
        &fixture,
        directory.path(),
        &create,
        Some(&witness.writer),
        address,
        true,
    ));
    running.finish();
    let current = witness.current(&fixture.policy);
    for fault in 0..3 {
        let mut value = config(&fixture, &witness, "open_existing");
        let mut listen = address;
        let selected = fault != 0;
        match fault {
            0 => {
                value["schema"] = "native-pq-tls-loopback-config-v2".into();
                value.as_object_mut().unwrap().remove("endpoint");
            }
            1 => value["endpoint"]["allowed_client_ips"] = json!(["127.0.0.2"]),
            2 => {
                listen.set_port(if address.port() == 65535 {
                    65534
                } else {
                    address.port() + 1
                });
                value["endpoint"]["server_address"] = listen.to_string().into();
            }
            _ => unreachable!(),
        }
        let output = command(
            &fixture,
            directory.path(),
            &value,
            Some(&witness.writer),
            listen,
            selected,
        )
        .output()
        .unwrap();
        assert!(!output.status.success(), "reopened changed policy {fault}");
        assert!(output.stdout.is_empty());
        assert_eq!(witness.current(&fixture.policy), current);
    }
}
