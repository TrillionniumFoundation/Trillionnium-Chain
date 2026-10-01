//! Actual signed native evaluation, SQLite restart and heavier-fork observations.
use serde_json::{json, Value};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation as evaluation};
use trnm_pon_node::{development_public, EvaluationPhase, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const NOW: u64 = 1_800_010_000;

fn signed(cfg: &Config, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut tx = Envelope {
        network: cfg.network,
        sender: development_public(who).unwrap(),
        nonce,
        expiry: 256,
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
fn contribution(cfg: &Config, nonce: u64, artifact: Hash, components: Hash) -> (Hash, Vec<u8>) {
    let owner = development_public(3).unwrap();
    let cid = hash(
        b"contribution-v3",
        &[
            &owner,
            &cfg.family,
            &[0; 32],
            &artifact,
            &components,
            &0_u64.to_le_bytes(),
        ],
    );
    let mut payload = Vec::new();
    for h in [cid, cfg.family, [0; 32], artifact] {
        payload.extend(h);
    }
    payload.extend(1024_u64.to_le_bytes());
    payload.extend(components);
    payload.extend(0_u64.to_le_bytes());
    (cid, signed(cfg, 3, nonce, 6, payload))
}
fn commit(cfg: &Config, cid: Hash, e: &Value, who: u64, score: u64, nonce: u64) -> Vec<u8> {
    let round = evaluation::round(e).unwrap();
    let commitment = evaluation::reveal_commitment(
        round,
        cid,
        development_public(who).unwrap(),
        cfg.plan,
        [9; 32],
        score,
        [who as u8 + 1; 32],
    );
    let mut p = cid.to_vec();
    p.extend(round);
    p.extend(commitment);
    signed(cfg, who, nonce, 14, p)
}
fn reveal(cfg: &Config, cid: Hash, e: &Value, who: u64, nonce: u64) -> Vec<u8> {
    let mut p = cid.to_vec();
    for h in [evaluation::round(e).unwrap(), cfg.plan, [9; 32]] {
        p.extend(h);
    }
    p.extend(10_u64.to_le_bytes());
    p.extend([who as u8 + 1; 32]);
    signed(cfg, who, nonce, 15, p)
}
fn append(node: &mut Node, height: u64, txs: Vec<Vec<u8>>) -> Hash {
    let packet = node
        .make(
            node.active().unwrap().0,
            txs,
            development_public(3).unwrap(),
            1_800_000_000 + height * 10,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, NOW).unwrap();
    node.activate_observed(id, NOW).unwrap();
    id
}
fn error<T>(result: trnm_pon_node::Result<T>, expected: &str) {
    match result {
        Ok(_) => panic!("expected {expected}"),
        Err(e) => assert_eq!(e.to_string(), expected),
    }
}

#[test]
fn actual_native_round_confirmation_restart_claim_late_conflict_and_heavier_fork() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(directory.path(), settings.clone(), 4).unwrap();
    let (cid, component) = contribution(&cfg, 1, [7; 32], [8; 32]);
    let allocation = hash(
        b"allocation-leaf",
        &[&cid, &development_public(3).unwrap(), &10_u64.to_le_bytes()],
    );
    let (bundle, bundle_tx) = contribution(&cfg, 2, [10; 32], allocation);
    let (missing, missing_tx) = contribution(&cfg, 3, [12; 32], [11; 32]);
    let budget = 10_000_u64;
    let release = hash(
        b"release",
        &[
            &[0; 32],
            &bundle,
            &budget.to_le_bytes(),
            &allocation,
            &10_u64.to_le_bytes(),
        ],
    );
    append(&mut node, 1, vec![component, bundle_tx, missing_tx]);
    let stats_before = node.stats().unwrap();
    let first = node.evaluation_observation(cid, NOW, 128).unwrap();
    assert_eq!(first.admitted_phase(), EvaluationPhase::Candidate);
    assert!(!first.candidate_anchor().confirmed());
    assert_eq!(first.confirmed_phase(), None);
    error(
        node.evaluation_observation(cid, NOW, 0),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    error(
        node.evaluation_observation(cid, NOW, 4097),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    error(node.evaluation_observation([1; 32], NOW, 128), "STATE");
    assert_eq!(node.stats().unwrap(), stats_before);
    for height in 2..=54 {
        let state = node.read_active().unwrap().2;
        let txs = match height {
            16 => {
                let mut txs = Vec::new();
                for who in 0..3 {
                    for (i, id) in [cid, bundle].into_iter().enumerate() {
                        let e = evaluation::read_evaluation(&state, id).unwrap();
                        txs.push(commit(&cfg, id, &e, who, 10, i as u64 + 1));
                    }
                }
                txs
            }
            32 => {
                let mut txs = Vec::new();
                for who in 0..3 {
                    for (i, id) in [cid, bundle].into_iter().enumerate() {
                        let e = evaluation::read_evaluation(&state, id).unwrap();
                        txs.push(reveal(&cfg, id, &e, who, i as u64 + 3));
                    }
                }
                txs
            }
            _ => vec![],
        };
        append(&mut node, height, txs);
        if height == 16 {
            let observation = node.evaluation_observation(cid, NOW, 128).unwrap();
            assert_eq!(observation.admitted_phase(), EvaluationPhase::Commit);
            assert_eq!(
                observation.confirmed_phase(),
                Some(EvaluationPhase::Candidate)
            );
        }
        if height == 32 {
            let observation = node.evaluation_observation(cid, NOW, 128).unwrap();
            assert_eq!(observation.admitted_phase(), EvaluationPhase::Reveal);
            assert_eq!(observation.confirmed_phase(), Some(EvaluationPhase::Commit));
        }
        if height == 48 {
            let observation = node.evaluation_observation(cid, NOW, 128).unwrap();
            assert_eq!(observation.closed_result().unwrap()["score"], 10);
            assert!(!observation.closure_anchor().unwrap().confirmed());
            assert_eq!(observation.confirmed_phase(), Some(EvaluationPhase::Reveal));
        }
    }
    let checkpoint = node.evaluation_observation(cid, NOW, 128).unwrap();
    assert_eq!(checkpoint.confirmed_prefix_height(), 48);
    assert!(checkpoint.closure_anchor().unwrap().confirmed());
    assert_eq!(checkpoint.closure_anchor().unwrap().height(), 48);
    assert_eq!(checkpoint.confirmed_phase(), Some(EvaluationPhase::Dispute));
    let aborted = node.evaluation_observation(missing, NOW, 128).unwrap();
    assert_eq!(aborted.closed_result().unwrap()["status"], "aborted");
    assert!(aborted.closed_result().unwrap()["score"].is_null());
    assert!(aborted.closure_anchor().unwrap().confirmed());
    error(
        node.evaluation_observation(cid, NOW, 53),
        "EVALUATION_OBSERVATION_LIMIT",
    );
    error(
        node.check_evaluation_observation(&checkpoint, 1_800_000_000, 128),
        "TIME_DEFERRED",
    );
    drop(node);
    let mut node = Node::open(directory.path(), settings.clone(), 2).unwrap();
    let reopened = node.evaluation_observation(cid, NOW, 128).unwrap();
    assert_eq!(
        serde_json::to_value(&checkpoint).unwrap(),
        serde_json::to_value(&reopened).unwrap()
    );
    node.check_evaluation_observation(&checkpoint, NOW, 128)
        .unwrap();
    for height in 55..=80 {
        let state = node.read_active().unwrap().2;
        let txs = match height {
            56 => {
                let mut p = release.to_vec();
                p.extend([0; 32]);
                p.extend(bundle);
                p.extend(budget.to_le_bytes());
                p.extend(allocation);
                p.extend(10_u64.to_le_bytes());
                p.push(1);
                p.extend(cid);
                p.extend(10_u64.to_le_bytes());
                vec![signed(&cfg, 3, 4, 8, p)]
            }
            58 => {
                let e = evaluation::read_evaluation(&state, cid).unwrap();
                let mut p = cid.to_vec();
                p.extend(evaluation::closed_digest(&e).unwrap());
                p.extend([1; 32]);
                p.extend([2; 32]);
                vec![signed(&cfg, 3, 5, 17, p)]
            }
            76 => {
                let mut p = release.to_vec();
                p.extend(cid);
                p.extend(10_u64.to_le_bytes());
                p.push(0);
                vec![signed(&cfg, 3, 6, 9, p)]
            }
            80 => {
                let e = evaluation::read_evaluation(&state, cid).unwrap();
                let first = commit(&cfg, cid, &e, 0, 10, 1);
                let second = commit(&cfg, cid, &e, 0, 11, 5);
                let mut p = cid.to_vec();
                p.extend((first.len() as u16).to_le_bytes());
                p.extend(first);
                p.extend((second.len() as u16).to_le_bytes());
                p.extend(second);
                vec![signed(&cfg, 3, 7, 16, p)]
            }
            _ => vec![],
        };
        append(&mut node, height, txs);
        if height == 56 {
            let o = node.evaluation_observation(cid, NOW, 128).unwrap();
            assert_eq!(o.admitted_phase(), EvaluationPhase::AdoptionWindow);
            assert_eq!(o.confirmed_phase(), Some(EvaluationPhase::Dispute));
        }
        if height == 62 {
            assert_eq!(
                node.evaluation_observation(cid, NOW, 128)
                    .unwrap()
                    .confirmed_phase(),
                Some(EvaluationPhase::AdoptionWindow)
            );
        }
    }
    let observed = node.evaluation_observation(cid, NOW, 128).unwrap();
    let json = serde_json::to_value(&observed).unwrap();
    assert_eq!(json["current_conflict_count"], 1);
    assert_eq!(json["closed_result"]["score"], 10);
    for field in [
        "finalized",
        "adoption_authority",
        "reward_authority",
        "execution_authority",
        "independent_governance_accepted",
        "objective_model_quality",
        "public_ready",
    ] {
        assert_eq!(json[field], false);
    }
    assert_eq!(
        node.read_active().unwrap().2[&format!("release:{}", hex::encode(release))]["remaining"],
        0
    );
    error(
        node.check_evaluation_observation(&checkpoint, NOW, 128),
        "STALE_VIEW",
    );
    let other = tempfile::tempdir().unwrap();
    let legacy = Node::open(other.path(), Settings::development(None).unwrap(), 1).unwrap();
    error(
        legacy.evaluation_observation(cid, NOW, 128),
        "PUBLIC_EVAL_PROFILE",
    );
    error(
        legacy.check_evaluation_observation(&observed, NOW, 128),
        "EVALUATION_OBSERVATION_CONTEXT",
    );
    let mut parent = node.settings().genesis();
    for height in 1..=81 {
        let packet = node
            .make(
                parent,
                vec![],
                development_public(1).unwrap(),
                1_800_000_000 + height * 10,
                4096,
            )
            .unwrap();
        parent = node.admit(&packet, NOW).unwrap();
    }
    node.activate_observed(parent, NOW).unwrap();
    error(
        node.check_evaluation_observation(&observed, NOW, 128),
        "STALE_VIEW",
    );
    error(node.evaluation_observation(cid, NOW, 128), "STATE");
    drop(node);
    let reopened = Node::open(directory.path(), settings, 1).unwrap();
    error(reopened.evaluation_observation(cid, NOW, 128), "STATE");
    assert_eq!(
        serde_json::to_value(&checkpoint).unwrap()["adoption_authority"],
        json!(false)
    );
}
