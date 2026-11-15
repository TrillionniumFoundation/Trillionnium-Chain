//! Test-only public fixture exporter for the separate actual Hepta paired gate.
//! Export success prepares inputs; it is not an effect, consumer or deployment PASS.
use super::*;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "prepares exact public NPQ6 material for the separately selected paired native tests"]
fn export_ordinary_npq6_task_and_evaluator_control_material() {
    let source = std::env::var("HEPTA_PON_CHAIN_SOURCE").unwrap();
    assert!(
        source.len() == 40
            && source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let output = std::path::PathBuf::from(std::env::var("HEPTA_PON_NPQ6_FIXTURE_OUT").unwrap());
    assert!(output.is_absolute() && !output.exists());
    fs::create_dir(&output).unwrap();
    assert_eq!(output.canonicalize().unwrap(), output);
    let app = Application::new();
    let producer = tempfile::tempdir().unwrap();
    let mut node = app.open(&producer.path().join("producer"));
    let samples = app.samples(&mut node);
    app.assert_task_and_evaluator_state(&node, &samples);
    drop(node);
    let config = serde_json::to_vec(&app.configuration()).unwrap();
    fixture::put(&output.join("application.json"), &config);
    let mut cases = Vec::new();
    for (name, index, mismatch) in [
        ("task", 1, false),
        ("evaluator", 15, false),
        ("owner-mismatch", 1, true),
        ("provider-loader", 1, false),
    ] {
        let directory = output.join(name);
        fs::create_dir(&directory).unwrap();
        let receiver = directory.join("receiver");
        let mut node = if mismatch {
            let policy = PqNetworkPolicy::new_tls13(
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
            Node::open_with_pq_network(&receiver, app.tls.settings.clone(), 1, &policy).unwrap()
        } else {
            app.open(&receiver)
        };
        let now = trnm_pon_node::ingress::now().unwrap();
        for packet in &samples.packets[..index] {
            let id = node.admit(packet, now).unwrap();
            node.activate_observed(id, now).unwrap();
        }
        let target = &samples.packets[index];
        assert_eq!(
            node.exact_packet_observation(target).unwrap()["stored_exact"],
            false
        );
        let raw = target.encode_for_settings(&app.tls.settings).unwrap();
        assert!(raw.starts_with(b"PQP6"));
        fixture::put(&directory.join("packet.bin"), &raw);
        cases.push(
            serde_json::json!({"name":name,"target_block":hex::encode(target.id().unwrap()),
            "packet_sha256":hex::encode(Sha256::digest(&raw)),"expected_success":!mismatch}),
        );
        drop(node);
    }
    let config_value = app.configuration();
    let manifest = serde_json::json!({
        "schema":"ordinary-pon-npq6-paired-material-v1","chain_source":source,
        "configuration_sha256":hex::encode(Sha256::digest(&config)),
        "application_profile":"pon-native-pq-application-v6",
        "network":config_value["network"],"parameters":config_value["parameters"],
        "genesis":config_value["genesis"],"network_policy":config_value["network_policy"],
        "cases":cases,"public_test_material":true,"target_admitted":false,"production_activation":false
    });
    fixture::put(
        &output.join("manifest.json"),
        &serde_json::to_vec(&manifest).unwrap(),
    );
    println!("{}", manifest);
}
