use std::{fs, path::PathBuf};

#[test]
fn inert_safety_rules_source_contract_remains_narrow() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read manifest");
    let source = fs::read_to_string(manifest_dir.join("src/lib.rs")).expect("read lib source");
    let readme = fs::read_to_string(manifest_dir.join("README.md")).expect("read README");

    for required in [
        "application_valid_authority = false",
        "complete_vote_admission = false",
        "signer_authority = false",
        "state_seed_authority = false",
        "finalized_reference_authority = false",
        "persistence_authority = false",
        "external_cas_authority = false",
        "hsm_authority = false",
        "core_integration = false",
        "remote_wire = false",
        "observe_qc = false",
        "observe_tc = false",
        "runtime_activation = false",
        "production_candidate = false",
        "production_consensus_activation = false",
    ] {
        assert!(
            manifest.contains(required),
            "missing manifest truth: {required}"
        );
    }

    assert!(source.contains("trnm.consensus.safety-rules.state.v1"));
    assert!(source.contains("trnm.consensus.safety-rules.transition.v1"));
    assert!(source.contains("proposal\n            .verify("));
    assert!(readme.contains("inert consensus-safety candidate"));

    for forbidden in [
        "SigningKey",
        "SecretKey",
        "Pkcs8",
        "SignatureProducer",
        "sign_bytes",
        "pub fn sign(",
        "extends_lock: bool",
        "descends_finalized: bool",
        "payload_valid: bool",
        "rusqlite",
        "tokio",
        "std::net",
        "trnm-consensus-core",
        "trnm-consensus-safety-store",
        "trnm-native-application",
        "trnm-consensus-remote-signer-protocol",
    ] {
        assert!(
            !manifest.contains(forbidden) && !source.contains(forbidden),
            "forbidden authority/dependency surface: {forbidden}"
        );
    }
}
