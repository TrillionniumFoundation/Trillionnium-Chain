//! Real native ancestry beyond 4096; logical timestamps do not measure live cadence.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation as evaluation};
use trnm_pon_node::{development_public, EvaluationPhase, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const GENESIS: u64 = 1_800_000_000;
const NOW: u64 = GENESIS + 100_000;

fn signed(cfg: &Config, who: u64, account_sequence: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut tx = Envelope {
        network: cfg.network,
        sender: development_public(who).unwrap(),
        nonce: account_sequence,
        expiry: 8192,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn contribution(
    cfg: &Config,
    account_sequence: u64,
    artifact: Hash,
    round: u64,
) -> (Hash, Vec<u8>) {
    let owner = development_public(3).unwrap();
    let components = [8; 32];
    let cid = hash(
        b"contribution-v3",
        &[
            &owner,
            &cfg.family,
            &[0; 32],
            &artifact,
            &components,
            &round.to_le_bytes(),
        ],
    );
    let mut p = Vec::new();
    for h in [cid, cfg.family, [0; 32], artifact] {
        p.extend(h);
    }
    p.extend(1024_u64.to_le_bytes());
    p.extend(components);
    p.extend(round.to_le_bytes());
    (cid, signed(cfg, 3, account_sequence, 6, p))
}
fn commit(cfg: &Config, cid: Hash, e: &Value, who: u64) -> Vec<u8> {
    let round = evaluation::round(e).unwrap();
    let commitment = evaluation::reveal_commitment(
        round,
        cid,
        development_public(who).unwrap(),
        cfg.plan,
        [9; 32],
        10,
        [who as u8 + 1; 32],
    );
    let mut p = cid.to_vec();
    p.extend(round);
    p.extend(commitment);
    signed(cfg, who, 1, 14, p)
}
fn reveal(cfg: &Config, cid: Hash, e: &Value, who: u64) -> Vec<u8> {
    let mut p = cid.to_vec();
    for h in [evaluation::round(e).unwrap(), cfg.plan, [9; 32]] {
        p.extend(h);
    }
    p.extend(10_u64.to_le_bytes());
    p.extend([who as u8 + 1; 32]);
    signed(cfg, who, 2, 15, p)
}
fn append(node: &mut Node, height: u64, txs: Vec<Vec<u8>>, evidence: Option<&Path>) -> Hash {
    let packet = node
        .make(
            node.active().unwrap().0,
            txs,
            development_public(3).unwrap(),
            GENESIS + height * 10,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, NOW).unwrap();
    node.activate_observed(id, NOW).unwrap();
    if let Some(directory) = evidence {
        fs::write(
            directory.join("packets").join(format!("{height:05}.bin")),
            packet.encode().unwrap(),
        )
        .unwrap();
    }
    id
}
fn error<T>(result: trnm_pon_node::Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("expected {expected}"),
        Err(e) => assert_eq!(e.to_string(), expected),
    }
}

#[test]
fn first_round_matches_v1_and_local_window_never_constructs_a_global_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(directory.path(), settings, 2).unwrap();
    let (cid, raw) = contribution(&cfg, 1, [7; 32], 0);
    append(&mut node, 1, vec![raw], None);
    let early = node.evaluation_round_observation(cid, NOW, 1).unwrap();
    assert_eq!(early.confirmed_round_prefix_height(), None);
    assert_eq!(early.confirmed_phase(), None);
    for height in 2..=54 {
        append(&mut node, height, vec![], None);
    }
    let v1 = node.evaluation_observation(cid, NOW, 54).unwrap();
    let v2 = node.evaluation_round_observation(cid, NOW, 54).unwrap();
    assert_eq!(
        v1.confirmed_prefix_height(),
        v2.confirmed_round_prefix_height().unwrap()
    );
    assert_eq!(v1.confirmed_phase(), v2.confirmed_phase());
    assert_eq!(v1.closed_result(), v2.closed_result());
    let value = serde_json::to_value(v2).unwrap();
    assert_eq!(
        value["schema"],
        "native-evaluation-confirmed-round-observation-v2"
    );
    for flag in [
        "global_confirmed_prefix",
        "global_clock_history_checked",
        "finalized",
        "adoption_authority",
        "reward_authority",
        "execution_authority",
        "public_ready",
    ] {
        assert_eq!(value[flag], false);
    }
    assert_eq!(value["base_anchor"]["confirmation_evaluated"], false);
    error(
        node.evaluation_round_observation(cid, NOW, 53),
        "EVALUATION_OBSERVATION_LIMIT",
    );
}

#[test]
#[ignore = "actual 4097+ native blocks; bounded evidence campaign"]
fn actual_long_chain_round_close_archive_restart_fork_and_cli() {
    let directory = std::env::var_os("EVALUATION_ROUND_OBSERVATION_EVIDENCE_DIR")
        .map(std::path::PathBuf::from)
        .expect("fresh evidence directory required");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("packets")).unwrap();
    let settings = Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(&directory.join("store"), settings.clone(), 4).unwrap();
    let mut base = [0; 32];
    for height in 1..=4096 {
        let id = append(&mut node, height, vec![], Some(&directory));
        if height == 4096 {
            base = id;
        }
    }
    let (cid, raw) = contribution(&cfg, 1, [7; 32], 32);
    let (missing, missing_raw) = contribution(&cfg, 2, [10; 32], 32);
    append(&mut node, 4097, vec![raw, missing_raw], Some(&directory));
    error(
        node.evaluation_observation(cid, NOW, 4096),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    let first = node.evaluation_round_observation(cid, NOW, 2).unwrap();
    assert_eq!(first.admitted_phase(), EvaluationPhase::Candidate);
    assert_eq!(first.confirmed_phase(), None);
    assert_eq!(first.round_blocks_checked(), 2);
    error(
        node.evaluation_round_observation(cid, NOW, 1),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    for height in 4098..=4224 {
        let state = node.read_active().unwrap().2;
        let e = evaluation::read_evaluation(&state, cid).unwrap();
        let txs = match height {
            4112 => (0..3).map(|who| commit(&cfg, cid, &e, who)).collect(),
            4128 => (0..3).map(|who| reveal(&cfg, cid, &e, who)).collect(),
            _ => vec![],
        };
        append(&mut node, height, txs, Some(&directory));
        if [4112, 4128, 4144, 4150].contains(&height) {
            let v = node.evaluation_round_observation(cid, NOW, 256).unwrap();
            if height == 4144 {
                assert_eq!(v.closed_result().unwrap()["score"], 10);
                assert!(!v.closure_anchor().unwrap().confirmed());
            }
            if height == 4150 {
                assert!(v.closure_anchor().unwrap().confirmed());
                assert_eq!(v.confirmed_round_prefix_height(), Some(4144));
                assert_eq!(v.confirmed_phase(), Some(EvaluationPhase::Dispute));
                let txid: Hash = hex::decode(
                    serde_json::to_value(v.candidate_anchor()).unwrap()["transaction"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap();
                let block: Hash = hex::decode(
                    serde_json::to_value(v.candidate_anchor()).unwrap()["block"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap();
                let confirmation =
                    serde_json::to_value(node.confirmations(&[(txid, block)], NOW).unwrap())
                        .unwrap();
                assert_eq!(confirmation["observations"][0]["confirmed"], true);
                assert_eq!(
                    confirmation["observations"][0]["depth"],
                    serde_json::to_value(v.candidate_anchor()).unwrap()["depth"]
                );
                assert_eq!(
                    confirmation["observations"][0]["work_delta"],
                    serde_json::to_value(v.candidate_anchor()).unwrap()["work_delta"]
                );
            }
            fs::write(
                directory.join(format!("observation-{height}.json")),
                serde_json::to_vec_pretty(&v).unwrap(),
            )
            .unwrap();
        }
    }
    let state = node.read_active().unwrap().2;
    assert!(!state.contains_key(&format!("contribution:{}", hex::encode(cid))));
    assert!(state.contains_key(&format!("evaluation-archive:{}", hex::encode(cid))));
    let checkpoint = node.evaluation_round_observation(cid, NOW, 129).unwrap();
    assert_eq!(checkpoint.admitted_phase(), EvaluationPhase::RoundEnded);
    assert_eq!(
        checkpoint.confirmed_phase(),
        Some(EvaluationPhase::AdoptionWindow)
    );
    assert_eq!(checkpoint.round_blocks_checked(), 129);
    error(
        node.evaluation_round_observation(cid, NOW, 128),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    let aborted = node
        .evaluation_round_observation(missing, NOW, 129)
        .unwrap();
    assert_eq!(aborted.closed_result().unwrap()["status"], "aborted");
    assert!(aborted.closed_result().unwrap()["score"].is_null());
    error(
        node.check_evaluation_round_observation(&checkpoint, GENESIS, 129),
        "TIME_DEFERRED",
    );
    let stats = node.stats().unwrap();
    drop(node);
    let mut cli = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cli.args([
        "evaluation-round-observe",
        "--development",
        "--evaluation-policy",
        evaluation::PROFILE,
        "--candidate",
        &hex::encode(cid),
        "--round-blocks",
        "129",
        "--logical-now",
        &NOW.to_string(),
    ])
    .arg("--store")
    .arg(directory.join("store"));
    let output = cli.output().unwrap();
    fs::write(directory.join("cli.stdout"), &output.stdout).unwrap();
    fs::write(directory.join("cli.stderr"), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["result"],
        serde_json::to_value(&checkpoint).unwrap()
    );
    let mut node = Node::open(&directory.join("store"), settings, 4).unwrap();
    assert_eq!(node.stats().unwrap(), stats);
    assert_eq!(
        serde_json::to_value(node.evaluation_round_observation(cid, NOW, 129).unwrap()).unwrap(),
        serde_json::to_value(&checkpoint).unwrap()
    );
    let mut parent = base;
    fs::create_dir(directory.join("fork-packets")).unwrap();
    for height in 4097..=4225 {
        let packet = node
            .make(
                parent,
                vec![],
                development_public(2).unwrap(),
                GENESIS + height * 10,
                4096,
            )
            .unwrap();
        parent = node.admit(&packet, NOW).unwrap();
        fs::write(
            directory
                .join("fork-packets")
                .join(format!("{height:05}.bin")),
            packet.encode().unwrap(),
        )
        .unwrap();
    }
    node.activate_observed(parent, NOW).unwrap();
    error(
        node.check_evaluation_round_observation(&checkpoint, NOW, 256),
        "STALE_VIEW",
    );
    error(node.evaluation_round_observation(cid, NOW, 256), "STATE");
    fs::write(directory.join("completion.json"), serde_json::to_vec_pretty(&json!({
        "schema":"native-evaluation-long-round-local-test-v1", "actual_main_blocks":4224,
        "actual_fork_blocks":129, "candidate":hex::encode(cid), "archived_observation":checkpoint,
        "fork_tip":hex::encode(parent), "logical_timestamp_scope":true,
        "live_ten_second_cadence_measured":false, "work_replayed_by_observer":false,
        "public_ready":false, "hardness_accepted":false, "independent_evaluation_accepted":false,
    })).unwrap()).unwrap();
}
