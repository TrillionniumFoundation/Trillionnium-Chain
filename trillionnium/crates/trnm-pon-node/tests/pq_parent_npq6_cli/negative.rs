use super::*;
use fixture::{refused, with_configuration, with_raw_configuration};
use serde_json::json;
use std::net::TcpListener;

#[test]
fn ordinary_npq6_configuration_rejects_genesis_and_application_failures_before_owner() {
    let profile = Profile::new();
    for fault in 0..14 {
        let files = tempfile::tempdir().unwrap();
        let store = files.path().join("node");
        let command = profile.pair(files.path(), &store);
        let mut config = profile.configuration();
        let expected = match fault {
            0 => {
                config["accounts"] = json!([]);
                "PQ2_GENESIS_LIMIT"
            }
            // Small invalid SPKIs keep this input within the protected file
            // bound; the original constructor checks 65 accounts first.
            1 => {
                config["accounts"] = json!(vec![json!({"spki":"00","balance":1}); 65]);
                "PQ2_GENESIS_LIMIT"
            }
            2 => {
                config["accounts"][0]["spki"] = "00".into();
                "PQ2_KEY"
            }
            3 => {
                config["accounts"][1] = config["accounts"][0].clone();
                "PQ2_DUPLICATE_KEY"
            }
            4 => {
                for account in config["accounts"].as_array_mut().unwrap() {
                    account["balance"] = 0.into();
                }
                "PQ2_GENESIS_FUNDS"
            }
            5 => {
                config["accounts"][0]["balance"] = u64::MAX.into();
                "RANGE"
            }
            6 => {
                config["genesis_time"] = 0.into();
                "PQ2_GENESIS_LIMIT"
            }
            7 => {
                config["application"]["evaluators"]
                    .as_array_mut()
                    .unwrap()
                    .truncate(1);
                "PQ6_EVALUATOR_PINS"
            }
            8 => {
                config["application"]["evaluators"][0] = hex::encode([9_u8; 32]).into();
                "PQ6_EVALUATOR_PINS"
            }
            9 => {
                config["application"]["evaluators"][1] =
                    config["application"]["evaluators"][0].clone();
                "PQ_PARENT_NPQ6_DUPLICATE_EVALUATOR"
            }
            10 => {
                let original = config["application"]["evaluators"][0].as_str().unwrap();
                let upper = original.to_uppercase();
                assert_ne!(original, upper);
                config["application"]["evaluators"][0] = upper.into();
                "HASH"
            }
            11 => {
                config["application"]["evaluation_profile"] = "legacy-first-two-v3".into();
                "PQ6_PUBLIC_EVALUATION_REQUIRED"
            }
            12 => {
                config["application"]["model_profile"] = "not-an-installed-model".into();
                "MODEL_PROFILE"
            }
            13 => {
                config["application"]["evaluators"] = json!((1..=17_u8)
                    .map(|n| hex::encode([n; 32]))
                    .collect::<Vec<_>>());
                "PQ6_EVALUATOR_PINS"
            }
            _ => unreachable!(),
        };
        refused(
            with_configuration(command, files.path(), &config),
            &store,
            expected,
        );
    }
}

#[test]
fn ordinary_npq6_configuration_keeps_exact_schema_owner_null_and_external_pins() {
    let profile = Profile::new();
    for fault in 0..19 {
        let files = tempfile::tempdir().unwrap();
        let store = files.path().join("node");
        let command = profile.pair(files.path(), &store);
        let mut config = profile.configuration();
        let mut writer_flag = false;
        let expected = match fault {
            0 => {
                config["network"] = hex::encode([0_u8; 32]).into();
                "PQ_NETWORK_CONTEXT"
            }
            1 => {
                config["parameters"] = hex::encode([0_u8; 32]).into();
                "PQ_NETWORK_CONTEXT"
            }
            2 => {
                config["genesis"] = hex::encode([0_u8; 32]).into();
                "PQ_NETWORK_CONTEXT"
            }
            3 => {
                config["witness"] = Value::Null;
                "invalid type: null"
            }
            4 => {
                config["owner_profile"] = "witness_v4".into();
                "PQ_TLS_WITNESS_CONFIG_REQUIRED"
            }
            5 => {
                config["owner_profile"] = "witness_v4".into();
                config["witness"] = json!({"generation":1,"witness_spki":"00","writer_spki":"00",
                    "socket":"/unopened","node_mode":"create"});
                "--witness-writer-key"
            }
            6 => {
                writer_flag = true;
                "PQ_PARENT_NPQ6_OWNER_SELECTION"
            }
            7 => {
                config["witness"] = json!({"generation":1,"witness_spki":"00","writer_spki":"00",
                    "socket":"/unopened","node_mode":"create"});
                "PQ_PARENT_NPQ6_OWNER_SELECTION"
            }
            8 => {
                config["owner_profile"] = "network_v3".into();
                "unknown variant"
            }
            9 => {
                config.as_object_mut().unwrap().remove("owner_profile");
                "missing field"
            }
            10 => {
                config["migration_anchor"] = json!({"trusted":true});
                "unknown field"
            }
            11 => {
                config["accounts"][0]["private_key"] = "not-accepted".into();
                "unknown field"
            }
            12 => {
                config["application"]["authority"] = true.into();
                "unknown field"
            }
            13 => {
                config["production_activation"] = true.into();
                "unknown field"
            }
            14 => {
                config["schema"] = "native-pq-tls-loopback-config-v1".into();
                "unknown field"
            }
            15 => {
                config["schema"] = "native-pq-tls-loopback-config-v2".into();
                "unknown field"
            }
            16 => "duplicate field",
            17 => "PQ_TLS_CONFIG_PIN",
            18 => "PQ_TLS_INPUT_LENGTH",
            _ => unreachable!(),
        };
        let mut raw = serde_json::to_vec(&config).unwrap();
        if fault == 16 {
            let text = String::from_utf8(raw).unwrap();
            let key = "\"schema\":\"native-pq-parent-npq6-tls-loopback-config-v1\"";
            assert_eq!(text.matches(key).count(), 1);
            raw = text.replacen(key, &format!("{key},{key}"), 1).into_bytes();
        }
        if fault == 18 {
            raw.resize(262_145, b' ');
        }
        let mut command = with_raw_configuration(command, files.path(), &raw);
        if writer_flag {
            command.args(["--witness-writer-key", "/never-opened"]);
        }
        if fault == 17 {
            command = support::replace_arg(command, "--tls-config-sha256", hex::encode([0_u8; 32]));
        }
        refused(command, &store, expected);
    }
}

#[test]
fn ordinary_npq6_existing_owner_context_cannot_be_replaced_by_a_valid_new_genesis_config() {
    let profile = Profile::new();
    let files = tempfile::tempdir().unwrap();
    let store = files.path().join("node");
    let original =
        Node::open_with_pq_network(&store, profile.tls.settings.clone(), 1, &profile.tls.policy)
            .unwrap();
    let tip = original.active().unwrap().0;
    drop(original);
    let mut accounts = profile.accounts.clone();
    accounts[0].balance += 1;
    let changed = Settings::native_pq_application_v6(
        &accounts,
        profile.tls.settings.genesis_time(),
        &profile.application,
    )
    .unwrap();
    assert_ne!(changed.network(), profile.tls.settings.network());
    let mut config = profile.configuration();
    config["accounts"][0]["balance"] = accounts[0].balance.into();
    config["network"] = hex::encode(changed.network()).into();
    config["parameters"] = hex::encode(changed.parameters()).into();
    config["genesis"] = hex::encode(changed.genesis()).into();
    let command = profile.pair(files.path(), &store);
    // All supplied new context digests are correct. This refusal must occur at
    // the existing owner, without deriving genesis from or migrating its DB.
    let output = with_configuration(command, files.path(), &config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let original =
        Node::open_with_pq_network(&store, profile.tls.settings.clone(), 1, &profile.tls.policy)
            .unwrap();
    assert_eq!(original.active().unwrap().0, tip);
    assert_eq!(
        original.settings().network(),
        profile.tls.settings.network()
    );
    assert_eq!(
        original.pq_network_status(&profile.tls.policy).unwrap()["records"],
        0
    );
}

#[test]
fn ordinary_npq6_and_legacy_packet_namespaces_do_not_auto_select_each_other() {
    let profile = Profile::new();
    let legacy = Fixture::new();
    let new_dir = tempfile::tempdir().unwrap();
    let old_dir = tempfile::tempdir().unwrap();
    let mut new_node = Node::open_with_pq_network(
        new_dir.path(),
        profile.tls.settings.clone(),
        1,
        &profile.tls.policy,
    )
    .unwrap();
    let old_node =
        Node::open_with_pq_network(old_dir.path(), legacy.settings.clone(), 1, &legacy.policy)
            .unwrap();
    let npq = profile
        .packets(&mut new_node, 1)
        .remove(0)
        .encode_for_settings(&profile.tls.settings)
        .unwrap();
    let old = old_node
        .make(
            legacy.settings.genesis(),
            vec![],
            trnm_pon_node::development_public(0).unwrap(),
            legacy.settings.genesis_time() + 10,
            4096,
        )
        .unwrap()
        .encode_for_settings(&legacy.settings)
        .unwrap();
    assert!(npq.starts_with(b"PQP6") && !old.starts_with(b"PQP6"));
    drop((new_node, old_node));
    for npq6_selected in [true, false] {
        let files = tempfile::tempdir().unwrap();
        let native = TcpListener::bind("127.0.0.1:0").unwrap();
        let history = TcpListener::bind("127.0.0.1:0").unwrap();
        native.set_nonblocking(true).unwrap();
        history.set_nonblocking(true).unwrap();
        let bound = json!({"native_listen":native.local_addr().unwrap().to_string(),
            "history_listen":history.local_addr().unwrap().to_string()});
        let packet = files.path().join("mismatched.packet");
        let campaign = files.path().join("campaign");
        put(&packet, if npq6_selected { &old } else { &npq }, false);
        let mut command = if npq6_selected {
            profile.recover(
                files.path(),
                new_dir.path(),
                &campaign,
                &packet,
                &bound,
                false,
            )
        } else {
            support::recovery(
                &legacy,
                files.path(),
                old_dir.path(),
                &campaign,
                &packet,
                &bound,
                false,
            )
        };
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(!campaign.exists());
        assert!(matches!(native.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        assert!(matches!(history.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}
