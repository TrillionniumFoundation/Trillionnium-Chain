//! Real executable reads a closed native store; no network or transport fixture.
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation as evaluation};
use trnm_pon_node::{development_public, ingress, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn command(store: &Path, genesis: u64, policy: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    c.arg("evaluation-round-observe")
        .arg("--development")
        .arg("--store")
        .arg(store)
        .args([
            "--genesis-time",
            &genesis.to_string(),
            "--evaluation-policy",
            policy,
        ]);
    c
}
fn failure(output: Output, expected: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn success(c: &mut Command) -> Value {
    let output = c.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn candidate(node: &Node, cfg: &Config) -> (Hash, Vec<u8>) {
    let owner = development_public(3).unwrap();
    let cid = hash(
        b"contribution-v3",
        &[
            &owner,
            &cfg.family,
            &[0; 32],
            &[7; 32],
            &[8; 32],
            &0_u64.to_le_bytes(),
        ],
    );
    let mut payload = Vec::new();
    for h in [cid, cfg.family, [0; 32], [7; 32]] {
        payload.extend(h);
    }
    payload.extend(1024_u64.to_le_bytes());
    payload.extend([8; 32]);
    payload.extend(0_u64.to_le_bytes());
    let mut tx = Envelope {
        network: node.settings().network(),
        sender: owner,
        nonce: 1,
        expiry: 128,
        fee_limit: 1_000_000,
        tag: 6,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&3_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    (cid, tx.encode().unwrap())
}

#[test]
fn round_query_hash_bounds_and_unknown_options_reject_before_store_creation() {
    let parent = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap().saturating_sub(2000);
    for bad in ["bad".to_owned(), "AA".repeat(32)] {
        let store = parent.path().join(format!("hash-{}", bad.len()));
        failure(
            command(&store, genesis, evaluation::PROFILE)
                .args(["--candidate", &bad])
                .output()
                .unwrap(),
            "HASH",
        );
        assert!(!store.exists());
    }
    for bound in ["0", "4097", "18446744073709551615"] {
        let store = parent.path().join(format!("bound-{bound}"));
        failure(
            command(&store, genesis, evaluation::PROFILE)
                .args([
                    "--candidate",
                    &hex::encode([1; 32]),
                    "--round-blocks",
                    bound,
                ])
                .output()
                .unwrap(),
            "EVALUATION_OBSERVATION_LIMIT",
        );
        assert!(!store.exists());
    }
    for (option, value) in [
        ("--height", "48"),
        ("--ancestry-blocks", "128"),
        ("--peer", "127.0.0.1:1"),
        ("--auth-secret", "not-opened"),
        ("--pool-policy", "not-opened"),
        ("--seconds", "1"),
        ("--clock", "1"),
    ] {
        let store = parent.path().join(option.trim_start_matches('-'));
        failure(
            command(&store, genesis, evaluation::PROFILE)
                .args(["--candidate", &hex::encode([1; 32]), option, value])
                .output()
                .unwrap(),
            &format!("UNKNOWN_OPTION:{option}"),
        );
        assert!(!store.exists());
    }
    for flag in [
        "--mine",
        "--public-development-network",
        "--authenticated-development-network",
    ] {
        let store = parent.path().join(flag.trim_start_matches('-'));
        failure(
            command(&store, genesis, evaluation::PROFILE)
                .args(["--candidate", &hex::encode([1; 32]), flag])
                .output()
                .unwrap(),
            &format!("UNKNOWN_OPTION:{flag}"),
        );
        assert!(!store.exists());
    }
}

#[test]
fn closed_round_archive_query_matches_api_and_restart_and_preserves_false_authority() {
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("native");
    let now = ingress::now().unwrap();
    let genesis = now.saturating_sub(2000);
    let settings =
        Settings::development_with_evaluation_policy(Some(genesis), evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(&store, settings.clone(), 1).unwrap();
    let (cid, raw) = candidate(&node, &cfg);
    for height in 1..=128 {
        let packet = node
            .make(
                node.active().unwrap().0,
                if height == 1 {
                    vec![raw.clone()]
                } else {
                    vec![]
                },
                development_public(3).unwrap(),
                genesis + height * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, now).unwrap();
        node.activate_observed(id, now).unwrap();
    }
    let active = node.read_active().unwrap().2;
    assert!(!active.contains_key(&format!("contribution:{}", hex::encode(cid))));
    assert!(active.contains_key(&format!("evaluation-archive:{}", hex::encode(cid))));
    let expected =
        serde_json::to_value(node.evaluation_round_observation(cid, now, 4096).unwrap()).unwrap();
    let stats = node.stats().unwrap();
    drop(node);
    let first = success(command(&store, genesis, evaluation::PROFILE).args([
        "--candidate",
        &hex::encode(cid),
        "--logical-now",
        &now.to_string(),
    ]));
    assert_eq!(first["result"], expected);
    assert_eq!(first["clock_scope"], "logical-test");
    assert_eq!(first["result"]["closed_result"]["status"], "aborted");
    assert!(first["result"]["closed_result"]["score"].is_null());
    assert_eq!(first["result"]["candidate_anchor"]["confirmed"], true);
    assert_eq!(first["result"]["closure_anchor"]["confirmed"], true);
    for flag in [
        "adoption_authority",
        "reward_authority",
        "execution_authority",
        "finalized",
        "independent_governance_accepted",
        "objective_model_quality",
        "public_ready",
        "global_confirmed_prefix",
        "global_clock_history_checked",
    ] {
        assert_eq!(first["result"][flag], false);
    }
    let default = success(
        command(&store, genesis, evaluation::PROFILE).args(["--candidate", &hex::encode(cid)]),
    );
    assert_eq!(default["clock_scope"], "local-wall");
    assert_eq!(default["result"]["candidate"], expected["candidate"]);
    assert_eq!(default["result"]["round"], expected["round"]);
    failure(
        command(&store, genesis, evaluation::PROFILE)
            .args(["--candidate", &hex::encode(cid), "--round-blocks", "127"])
            .output()
            .unwrap(),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    failure(
        command(&store, genesis, evaluation::PROFILE)
            .args([
                "--candidate",
                &hex::encode(cid),
                "--logical-now",
                &genesis.to_string(),
            ])
            .output()
            .unwrap(),
        "TIME_DEFERRED",
    );
    failure(
        command(&store, genesis, evaluation::PROFILE)
            .args(["--candidate", &hex::encode([1; 32])])
            .output()
            .unwrap(),
        "STATE",
    );
    let reopened = Node::open(&store, settings, 1).unwrap();
    assert_eq!(reopened.stats().unwrap(), stats);
    assert_eq!(
        serde_json::to_value(
            reopened
                .evaluation_round_observation(cid, now, 4096)
                .unwrap()
        )
        .unwrap(),
        expected
    );
    drop(reopened);
    let historical = directory.path().join("historical");
    drop(
        Node::open(
            &historical,
            Settings::development(Some(genesis)).unwrap(),
            1,
        )
        .unwrap(),
    );
    failure(
        command(&historical, genesis, "legacy-first-two-v3")
            .args(["--candidate", &hex::encode(cid)])
            .output()
            .unwrap(),
        "PUBLIC_EVAL_PROFILE",
    );
}
