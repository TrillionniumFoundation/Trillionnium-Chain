//! Explicit revision16 selector and actual tag24 PNW1/store/observation replay.
//! The tiny constant-output candidate tests mechanics, not model efficacy.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    model_evidence_v3, model_evolution_v5 as evolution,
    model_task_windows_v1::{self as windows, PinnedTaskWindows, SignedTaskWindows},
    pon_executor::Config,
    public_evaluation as evaluation,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    integer_evolution_v3::EvolutionOperationV3,
    pon_wire::{hash, Envelope, Hash},
};

const WINDOW_MANIFEST: &[u8] = include_bytes!(
    "../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.manifest.json"
);
fn window_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../formal/pon-nakamoto-v1/vectors/model-task-windows-v1.json"
    ))
    .unwrap()
}
fn digest(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn status(store: &Path, model: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "status",
            "--development",
            "--genesis-time",
            "1",
            "--evaluation-policy",
            evaluation::QUORUM_PROFILE,
            "--model-profile",
            model,
            "--workers",
            "2",
        ])
        .arg("--store")
        .arg(store)
        .output()
        .unwrap()
}
#[test]
fn explicit_revision16_cli_is_distinct_reopens_and_refuses_revision15_store() {
    let directory = tempfile::tempdir().unwrap();
    let evolution_path = directory.path().join("evolution");
    let historical_path = directory.path().join("historical");
    let newer = status(&evolution_path, evolution::PROFILE);
    assert!(
        newer.status.success(),
        "{}",
        String::from_utf8_lossy(&newer.stderr)
    );
    let old = status(&historical_path, model_evidence_v3::PROFILE);
    assert!(
        old.status.success(),
        "{}",
        String::from_utf8_lossy(&old.stderr)
    );
    let newer: Value = serde_json::from_slice(&newer.stdout).unwrap();
    let old: Value = serde_json::from_slice(&old.stdout).unwrap();
    for field in ["network", "parameters", "genesis"] {
        assert_ne!(newer["result"][field], old["result"][field], "{field}");
    }
    assert_eq!(newer["result"]["production_activation"], false);
    let reopened = status(&evolution_path, evolution::PROFILE);
    assert!(reopened.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&reopened.stdout).unwrap(),
        newer
    );
    assert_eq!(
        status(&evolution_path, model_evidence_v3::PROFILE)
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        status(&historical_path, evolution::PROFILE).status.code(),
        Some(2)
    );
}

#[test]
fn signed_joint_update_has_native_packet_membership_and_survives_store_reopen() {
    packet_membership_reopen(false);
}
#[test]
fn external_window_has_real_pnw1_membership_and_pinned_store_reopen() {
    packet_membership_reopen(true);
}
fn packet_membership_reopen(windowed: bool) {
    let directory = tempfile::tempdir().unwrap();
    let vector = window_vector();
    let input = windowed.then_some(PinnedTaskWindows {
        raw: WINDOW_MANIFEST,
        sha256: digest(&vector["sha256"]),
        owner: digest(&vector["owner"]),
    });
    let cfg = Config::installed_with_model_profiles_and_task_windows(
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        evolution::PROFILE,
        input,
    )
    .unwrap();
    let settings = Settings::development_with_model_profiles_and_task_windows(
        None,
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        evolution::PROFILE,
        input,
    )
    .unwrap();
    let genesis = settings.genesis();
    let mut node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let initial = node.read_active().unwrap().2;
    let mut router = vec![0; 260];
    router[1] = 1;
    router[259] = 1;
    let mut expert = vec![0; 260];
    expert[2] = 1;
    expert[259] = 2;
    let witness = evolution::build_witness(
        &initial,
        &cfg,
        development_public(0).unwrap(),
        0,
        7,
        vec![
            EvolutionOperationV3 {
                target: 1,
                rank: 1,
                factors: router,
            },
            EvolutionOperationV3 {
                target: 3,
                rank: 1,
                factors: expert,
            },
        ],
        [8; 32],
    )
    .unwrap();
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut envelope = Envelope {
        network: cfg.network,
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 128,
        fee_limit: 1_000_000,
        tag: 24,
        payload: witness.encode().unwrap(),
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let packet = node
        .make(
            genesis,
            vec![envelope.encode().unwrap()],
            development_public(3).unwrap(),
            settings.genesis_time() + 10,
            4096,
        )
        .unwrap();
    let tip = node.admit(&packet, settings.genesis_time() + 1000).unwrap();
    node.activate(tip).unwrap();
    let state = node.read_active().unwrap().2;
    let record = evolution::evidence(&state, witness.contribution_id).unwrap();
    assert_eq!(record["schema"], "native-integer-model-evidence-record-v5");
    assert_eq!(record["independent_accepted"], false);
    if windowed {
        assert_eq!(record["rows"], 6);
        assert_eq!(record["task_window"]["owner"], vector["owner"]);
        assert_eq!(record["tasks"], observation_material(&cfg)["tasks_root"]);
    }
    assert_eq!(
        evolution::current_model(&state, &cfg).unwrap().id(),
        witness.parent_artifact
    );
    let observation = node
        .evaluation_observation(witness.contribution_id, settings.genesis_time() + 1000, 10)
        .unwrap();
    let observation = serde_json::to_value(observation).unwrap();
    assert_eq!(
        observation["candidate_anchor"]["transaction_membership_verified"],
        true
    );
    assert_eq!(observation["candidate_anchor"]["block"], hex::encode(tip));
    assert_eq!(observation["adoption_authority"], false);
    drop(node);
    let reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(reopened.read_active().unwrap().2, state);
    assert_eq!(
        serde_json::to_value(
            reopened
                .evaluation_observation(
                    witness.contribution_id,
                    cfg.params["genesis_timestamp"].as_u64().unwrap() + 1000,
                    10
                )
                .unwrap()
        )
        .unwrap(),
        observation
    );
    let incompatible = Settings::development_with_model_profiles(
        None,
        evaluation::QUORUM_PROFILE,
        "legacy-task-v1",
        model_evidence_v3::PROFILE,
    )
    .unwrap();
    assert!(Node::open(directory.path(), incompatible, 2).is_err());
}
fn observation_material(cfg: &Config) -> Value {
    model_evidence_v3::evaluation_material(cfg, 0).unwrap()
}
fn window_status(store: &Path, manifest: &Path, sha256: &str, owner: &str, mask: u8) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command
        .args([
            "status",
            "--development",
            "--genesis-time",
            "1",
            "--evaluation-policy",
            evaluation::QUORUM_PROFILE,
            "--model-profile",
            evolution::PROFILE,
            "--workers",
            "2",
        ])
        .arg("--store")
        .arg(store);
    if mask & 1 != 0 {
        command.arg("--model-task-windows").arg(manifest);
    }
    if mask & 2 != 0 {
        command.args(["--model-task-windows-sha256", sha256]);
    }
    if mask & 4 != 0 {
        command.args(["--model-data-owner", owner]);
    }
    command.output().unwrap()
}
#[test]
fn window_cli_requires_every_pin_and_refuses_substitution_wrong_owner_or_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = directory.path().join("windows.json");
    std::fs::write(&manifest_path, WINDOW_MANIFEST).unwrap();
    let vector = window_vector();
    let pin = vector["sha256"].as_str().unwrap();
    let owner = vector["owner"].as_str().unwrap();
    for mask in 1..7 {
        let store = directory.path().join(format!("incomplete-{mask}"));
        let rejected = window_status(&store, &manifest_path, pin, owner, mask);
        assert_eq!(rejected.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&rejected.stderr)
            .contains("TASK_WINDOW_COMPLETE_CONFIG_REQUIRED"));
        assert!(!store.exists());
    }
    let store = directory.path().join("window-store");
    let first = window_status(&store, &manifest_path, pin, owner, 7);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let repeated = window_status(&store, &manifest_path, pin, owner, 7);
    assert!(repeated.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&repeated.stdout).unwrap(),
        first
    );
    let default = status(&directory.path().join("no-window"), evolution::PROFILE);
    assert!(default.status.success());
    let default: Value = serde_json::from_slice(&default.stdout).unwrap();
    for field in ["network", "parameters", "genesis"] {
        assert_ne!(first["result"][field], default["result"][field]);
    }
    assert_eq!(status(&store, evolution::PROFILE).status.code(), Some(2));
    for (pin, owner, code) in [
        (hex::encode([0; 32]), owner.to_owned(), "TASK_WINDOW_PIN"),
        (pin.to_owned(), hex::encode([1; 32]), "TASK_WINDOW_OWNER"),
    ] {
        let result = window_status(
            &directory.path().join("bad-not-created"),
            &manifest_path,
            &pin,
            &owner,
            7,
        );
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains(code));
    }
    let mut altered: SignedTaskWindows = serde_json::from_slice(WINDOW_MANIFEST).unwrap();
    altered.owner_revision = 2;
    let family = digest(&vector["family"]);
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-TASK-WINDOW-OWNER",
        &[&0_u64.to_le_bytes()],
    )))
    .unwrap();
    altered.signature = sign_hex(&key, &windows::signing_digest(family, &altered).unwrap());
    let raw = serde_json::to_vec(&altered).unwrap();
    std::fs::write(&manifest_path, &raw).unwrap();
    let substitution = window_status(&store, &manifest_path, pin, owner, 7);
    assert_eq!(substitution.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&substitution.stderr).contains("TASK_WINDOW_PIN"));
    let changed_pin = hex::encode(Sha256::digest(&raw));
    assert_eq!(
        window_status(&store, &manifest_path, &changed_pin, owner, 7)
            .status
            .code(),
        Some(2)
    );
    let fresh = window_status(
        &directory.path().join("owner-revision-2"),
        &manifest_path,
        &changed_pin,
        owner,
        7,
    );
    assert!(
        fresh.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh.stderr)
    );
}
