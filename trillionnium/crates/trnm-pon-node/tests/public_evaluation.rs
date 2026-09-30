//! Native evaluation, release/reward and actual durable fork rollback.
use serde_json::{json, Value};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    pon_executor::{self, Config, State},
    public_evaluation as evaluation,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn signed(cfg: &Config, who: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut tx = Envelope {
        network: cfg.network,
        sender: hex::decode(public_key_hex(&key))
            .unwrap()
            .try_into()
            .unwrap(),
        nonce,
        expiry: 128,
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
fn initial(cfg: &Config) -> State {
    let mut state = State::from([
        ("meta:issued".into(), json!(40_000_000)),
        ("model:current".into(), json!(hex::encode([0; 32]))),
    ]);
    for i in 0..4 {
        state.insert(
            format!("account:{}", hex::encode(development_public(i).unwrap())),
            json!({"balance":10_000_000,"nonce":0}),
        );
    }
    assert!(!evaluation::enabled(&Config::installed().unwrap()));
    assert!(evaluation::enabled(cfg));
    state
}
fn contribute(cfg: &Config, nonce: u64, artifact: Hash, components: Hash) -> (Hash, Vec<u8>) {
    let who = development_public(3).unwrap();
    let cid = hash(
        b"contribution-v3",
        &[
            &who,
            &cfg.family,
            &[0; 32],
            &artifact,
            &components,
            &0_u64.to_le_bytes(),
        ],
    );
    let mut p = Vec::new();
    for value in [cid, cfg.family, [0; 32], artifact] {
        p.extend(value);
    }
    p.extend(1024_u64.to_le_bytes());
    p.extend(components);
    p.extend(0_u64.to_le_bytes());
    (cid, signed(cfg, 3, nonce, 6, p))
}
fn object(state: &State, cid: Hash) -> &Value {
    &state[&format!("contribution:{}", hex::encode(cid))]
}
fn step(state: &State, txs: &[Vec<u8>], height: u64, cfg: &Config) -> State {
    pon_executor::execute(
        state,
        txs,
        height,
        development_public(3).unwrap(),
        [4; 32],
        4,
        cfg,
    )
    .unwrap()
    .state
}
fn commit_tx(cfg: &Config, cid: Hash, eval: &Value, who: u64, score: u64, nonce: u64) -> Vec<u8> {
    let round = evaluation::round(eval).unwrap();
    let value = evaluation::reveal_commitment(
        round,
        cid,
        development_public(who).unwrap(),
        cfg.plan,
        [9; 32],
        score,
        [who as u8 + 1; 32],
    );
    let mut p = Vec::new();
    p.extend(cid);
    p.extend(round);
    p.extend(value);
    signed(cfg, who, nonce, 14, p)
}
fn reveal_tx(cfg: &Config, cid: Hash, eval: &Value, who: u64, score: u64, nonce: u64) -> Vec<u8> {
    let mut p = Vec::new();
    for value in [cid, evaluation::round(eval).unwrap(), cfg.plan, [9; 32]] {
        p.extend(value);
    }
    p.extend(score.to_le_bytes());
    p.extend([who as u8 + 1; 32]);
    signed(cfg, who, nonce, 15, p)
}
fn prepared() -> (Config, State, Hash, Hash) {
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let (cid, tx) = contribute(&cfg, 1, [7; 32], [8; 32]);
    let s = step(&initial(&cfg), &[tx], 1, &cfg);
    let round = evaluation::round(&object(&s, cid)["public_evaluation"]).unwrap();
    (cfg, s, cid, round)
}
#[test]
fn every_arrival_order_closes_identically_and_missing_is_abort() {
    let (cfg, base, cid, _) = prepared();
    let scores = [10, 100, 100];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let e = &object(&base, cid)["public_evaluation"];
        let mut s = step(
            &base,
            &order
                .iter()
                .map(|&i| commit_tx(&cfg, cid, e, i, scores[i as usize], 1))
                .collect::<Vec<_>>(),
            16,
            &cfg,
        );
        let e = &object(&s, cid)["public_evaluation"];
        s = step(
            &s,
            &order
                .iter()
                .map(|&i| reveal_tx(&cfg, cid, e, i, scores[i as usize], 2))
                .collect::<Vec<_>>(),
            32,
            &cfg,
        );
        assert_eq!(object(&s, cid)["status"], "submitted");
        s = step(&s, &[], 48, &cfg);
        assert_eq!(object(&s, cid)["score"], 10);
        assert_eq!(object(&s, cid)["status"], "evaluated");
        assert!(evaluation::adoption_allowed(&object(&s, cid)["public_evaluation"], 55).is_err());
        assert!(evaluation::adoption_allowed(&object(&s, cid)["public_evaluation"], 56).is_ok());
    }
    let s = step(&base, &[], 48, &cfg);
    assert_eq!(object(&s, cid)["status"], "evaluation-aborted");
    assert_eq!(object(&s, cid)["score"], 0);
}
#[test]
fn premature_wrong_salt_direct_votes_and_historical_profiles_are_refused() {
    let (cfg, base, cid, _) = prepared();
    let e = &object(&base, cid)["public_evaluation"];
    let commit = commit_tx(&cfg, cid, e, 0, 10, 1);
    assert!(pon_executor::execute(
        &base,
        std::slice::from_ref(&commit),
        15,
        [0; 32],
        [4; 32],
        2,
        &cfg
    )
    .is_err());
    let s = step(&base, std::slice::from_ref(&commit), 16, &cfg);
    let wrong = reveal_tx(&cfg, cid, e, 0, 11, 2);
    assert!(pon_executor::execute(&s, &[wrong], 32, [0; 32], [4; 32], 2, &cfg).is_err());
    let old = Config::installed().unwrap();
    assert!(
        pon_executor::execute(&initial(&cfg), &[commit], 16, [0; 32], [4; 32], 2, &old).is_err()
    );
    let mut p = Vec::new();
    p.extend(cid);
    p.extend(cfg.plan);
    p.extend([9; 32]);
    p.extend(10_u64.to_le_bytes());
    assert!(pon_executor::execute(
        &base,
        &[signed(&cfg, 0, 1, 7, p)],
        2,
        [0; 32],
        [4; 32],
        2,
        &cfg
    )
    .is_err());
}
#[test]
fn independently_verified_conflict_blocks_adoption_and_next_round_eligibility() {
    let (cfg, base, cid, _) = prepared();
    let e = &object(&base, cid)["public_evaluation"];
    let first = commit_tx(&cfg, cid, e, 0, 10, 1);
    let second = commit_tx(&cfg, cid, e, 0, 11, 2);
    let mut p = Vec::new();
    p.extend(cid);
    p.extend((first.len() as u16).to_le_bytes());
    p.extend(&first);
    p.extend((second.len() as u16).to_le_bytes());
    p.extend(&second);
    let s = step(&base, &[signed(&cfg, 3, 2, 16, p.clone())], 20, &cfg);
    assert!(s.contains_key(&format!(
        "evaluation-disqualified:{}",
        hex::encode(development_public(0).unwrap())
    )));
    let s = step(&s, &[], 48, &cfg);
    assert_eq!(object(&s, cid)["status"], "evaluation-aborted");
    p[34 + first.len() - 1] ^= 1;
    assert!(pon_executor::execute(
        &base,
        &[signed(&cfg, 3, 2, 16, p)],
        20,
        [0; 32],
        [4; 32],
        2,
        &cfg
    )
    .is_err());
    let mut candidate = object(&base, cid).clone();
    candidate["owner"] = json!(hex::encode(development_public(1).unwrap()));
    assert!(evaluation::freeze(&cfg, cid, &candidate, 128, &evaluation::excluded(&s)).is_err());
}
#[test]
fn appeals_preserve_closed_score_and_require_exact_result_binding() {
    let (cfg, base, cid, _) = prepared();
    let mut s = step(&base, &[], 48, &cfg);
    let e = &object(&s, cid)["public_evaluation"];
    let closed = e["closed"].clone();
    let result = evaluation::closed_digest(e).unwrap();
    let mut p = Vec::new();
    for value in [cid, result, [1; 32], [2; 32]] {
        p.extend(value);
    }
    let tx = signed(&cfg, 3, 2, 17, p.clone());
    s = step(&s, &[tx], 49, &cfg);
    assert_eq!(object(&s, cid)["public_evaluation"]["closed"], closed);
    p[32] ^= 1;
    assert!(pon_executor::execute(
        &s,
        &[signed(&cfg, 3, 3, 17, p)],
        50,
        [0; 32],
        [4; 32],
        2,
        &cfg
    )
    .is_err());
}
#[test]
fn actual_store_reopen_and_heavier_fork_remove_native_evaluation_state() {
    let temp = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_evaluation_policy(None, evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let mut node = Node::open(temp.path(), settings.clone(), 4).unwrap();
    let (cid, tx) = contribute(&cfg, 1, [7; 32], [8; 32]);
    let genesis = node.settings().genesis();
    let packet = node
        .make(
            genesis,
            vec![tx],
            development_public(3).unwrap(),
            1_800_000_010,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 1_800_010_000).unwrap();
    node.activate(id).unwrap();
    let e = object(&node.read_active().unwrap().2, cid)["public_evaluation"].clone();
    drop(node);
    let mut node = Node::open(temp.path(), settings.clone(), 2).unwrap();
    assert_eq!(
        object(&node.read_active().unwrap().2, cid)["public_evaluation"],
        e
    );
    let first = node
        .make(
            genesis,
            vec![],
            development_public(1).unwrap(),
            1_800_000_010,
            4096,
        )
        .unwrap();
    let fork = node.admit(&first, 1_800_010_000).unwrap();
    let second = node
        .make(
            fork,
            vec![],
            development_public(1).unwrap(),
            1_800_000_020,
            4096,
        )
        .unwrap();
    let tip = node.admit(&second, 1_800_010_000).unwrap();
    node.activate(tip).unwrap();
    assert!(!node
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("contribution:{}", hex::encode(cid))));
    drop(node);
    assert!(!Node::open(temp.path(), settings, 1)
        .unwrap()
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("contribution:{}", hex::encode(cid))));
}

#[test]
fn complete_native_evaluation_gates_release_and_mature_reward_and_preserves_appeal() {
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let (cid, component) = contribute(&cfg, 1, [7; 32], [8; 32]);
    let root = hash(
        b"allocation-leaf",
        &[&cid, &development_public(3).unwrap(), &10_u64.to_le_bytes()],
    );
    let (bundle, bundle_tx) = contribute(&cfg, 2, [10; 32], root);
    let mut s = step(&initial(&cfg), &[component, bundle_tx], 1, &cfg);
    let mut commits = Vec::new();
    for who in 0..3 {
        for (i, candidate) in [cid, bundle].into_iter().enumerate() {
            commits.push(commit_tx(
                &cfg,
                candidate,
                &object(&s, candidate)["public_evaluation"],
                who,
                10,
                i as u64 + 1,
            ));
        }
    }
    s = step(&s, &commits, 16, &cfg);
    let mut reveals = Vec::new();
    for who in 0..3 {
        for (i, candidate) in [cid, bundle].into_iter().enumerate() {
            reveals.push(reveal_tx(
                &cfg,
                candidate,
                &object(&s, candidate)["public_evaluation"],
                who,
                10,
                i as u64 + 3,
            ));
        }
    }
    s = step(&s, &reveals, 32, &cfg);
    s = step(&s, &[], 48, &cfg);
    let budget = 10_000_u64;
    let release = hash(
        b"release",
        &[
            &[0; 32],
            &bundle,
            &budget.to_le_bytes(),
            &root,
            &10_u64.to_le_bytes(),
        ],
    );
    let mut p = Vec::new();
    p.extend(release);
    p.extend([0; 32]);
    p.extend(bundle);
    p.extend(budget.to_le_bytes());
    p.extend(root);
    p.extend(10_u64.to_le_bytes());
    p.push(1);
    p.extend(cid);
    p.extend(10_u64.to_le_bytes());
    let tx = signed(&cfg, 3, 3, 8, p);
    assert!(
        pon_executor::execute(&s, std::slice::from_ref(&tx), 55, [0; 32], [4; 32], 2, &cfg)
            .is_err()
    );
    let missing = step(
        &initial(&cfg),
        &[
            contribute(&cfg, 1, [7; 32], [8; 32]).1,
            contribute(&cfg, 2, [10; 32], root).1,
        ],
        1,
        &cfg,
    );
    let missing = step(&missing, &[], 48, &cfg);
    assert!(pon_executor::execute(
        &missing,
        std::slice::from_ref(&tx),
        56,
        [0; 32],
        [4; 32],
        2,
        &cfg
    )
    .is_err());
    s = step(&s, &[tx], 56, &cfg);
    assert_eq!(s["model:current"], hex::encode(release));
    let closed = evaluation::closed_digest(&object(&s, cid)["public_evaluation"]).unwrap();
    s = step(&s, &[], 57, &cfg);
    assert!(!s.contains_key(&format!("contribution:{}", hex::encode(cid))));
    let mut appeal = Vec::new();
    for value in [cid, closed, [1; 32], [2; 32]] {
        appeal.extend(value);
    }
    s = step(&s, &[signed(&cfg, 3, 4, 17, appeal)], 58, &cfg);
    let archive = &s[&format!("evaluation-archive:{}", hex::encode(cid))];
    assert_eq!(archive["public_evaluation"]["closed"]["score"], 10);
    assert_eq!(
        archive["public_evaluation"]["appeals"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    let mut claim = Vec::new();
    claim.extend(release);
    claim.extend(cid);
    claim.extend(10_u64.to_le_bytes());
    claim.push(0);
    let tx = signed(&cfg, 3, 5, 9, claim);
    assert!(
        pon_executor::execute(&s, std::slice::from_ref(&tx), 75, [0; 32], [4; 32], 2, &cfg)
            .is_err()
    );
    s = step(&s, std::slice::from_ref(&tx), 76, &cfg);
    let rel = &s[&format!("release:{}", hex::encode(release))];
    assert_eq!(rel["remaining"], 0);
    assert_eq!(rel["claims"][hex::encode(cid)], budget);
    assert!(pon_executor::execute(&s, &[tx], 77, [0; 32], [4; 32], 2, &cfg).is_err());
    s = step(&s, &[], 305, &cfg);
    assert!(!s.contains_key(&format!("evaluation-archive:{}", hex::encode(cid))));
}
